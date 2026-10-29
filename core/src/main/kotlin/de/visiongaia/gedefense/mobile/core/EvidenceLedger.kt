package de.visiongaia.gedefense.mobile.core

import java.io.BufferedInputStream
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.security.MessageDigest
import java.security.SecureRandom
import java.time.Instant
import java.util.Base64
import javax.crypto.Mac
import javax.crypto.SecretKey

data class EvidenceEvent(
    val type: String,
    val severity: String,
    val subject: String,
    val detail: String,
    val atMillis: Long = System.currentTimeMillis(),
)

data class LedgerHealth(val ok: Boolean, val records: Long, val reason: String? = null, val invalidLine: Long? = null)
data class RecoveryResult(val archive: File, val manifest: File, val sha256: String)
data class RecoveryArchiveHealth(val ok: Boolean, val reason: String? = null)

// STATUS: DIAMANT VGT SUPREME
interface EvidenceStore {
    fun open(): LedgerHealth
    fun append(event: EvidenceEvent)
    fun verify(): LedgerHealth
    fun recover(archiveDir: File, reason: String): RecoveryResult
    fun verifyRecoveryArchive(manifest: File): RecoveryArchiveHealth
}

class EvidenceStoreUnavailableException(val reasonCode: String) :
    IOException("evidence store unavailable: $reasonCode")

/**
 * Explicit fail-closed Evidence capability used when key custody cannot be established.
 *
 * It never creates files, accepts writes, or reports a healthy empty ledger. This keeps process
 * availability independent from Android Keystore availability without weakening the protection
 * readiness invariant.
 */
class UnavailableEvidenceStore(reasonCode: String) : EvidenceStore {
    private val reason = reasonCode.also {
        require(FAILURE_CODE.matches(it)) { "invalid evidence failure code" }
    }

    override fun open(): LedgerHealth = unhealthy()

    override fun append(event: EvidenceEvent): Nothing = throw EvidenceStoreUnavailableException(reason)

    override fun verify(): LedgerHealth = unhealthy()

    override fun recover(archiveDir: File, reason: String): Nothing =
        throw IOException("evidence recovery unavailable while key custody is offline")

    override fun verifyRecoveryArchive(manifest: File): RecoveryArchiveHealth =
        RecoveryArchiveHealth(false, "evidence key custody unavailable")

    private fun unhealthy(): LedgerHealth = LedgerHealth(ok = false, records = 0L, reason = reason)

    companion object {
        private val FAILURE_CODE = Regex("evidence_[a-z0-9_]{3,80}")
    }
}

/**
 * Pluggable record confidentiality for EvidenceLedger.
 *
 * Implementations are responsible for authenticated encryption and must bind sequence/timestamp
 * to the protected payload. The core module deliberately knows nothing about AndroidKeyStore.
 */
interface EvidencePayloadProtector {
    @Throws(Exception::class)
    fun protect(sequence: Long, atMillis: Long, plaintext: ByteArray): ByteArray

    @Throws(Exception::class)
    fun unprotect(sequence: Long, atMillis: Long, protectedPayload: ByteArray): ByteArray
}

/**
 * Bounded, append-only, HMAC-chained evidence ledger.
 *
 * Format v3 adds per-record authenticated encryption while retaining the independent HMAC chain.
 * Legacy v2 plaintext records are accepted only long enough to perform a verified, atomic
 * migration when a protector is configured. Mixed-format ledgers are rejected.
 */
class EvidenceLedger(
    private val file: File,
    private val key: SecretKey,
    private val maxBytes: Long = 16L shl 20,
    private val protector: EvidencePayloadProtector? = null,
) : EvidenceStore {
    private enum class Format { EMPTY, LEGACY_V2, ENCRYPTED_V3 }

    private data class VerifyState(
        val health: LedgerHealth,
        val lastHash: String,
        val length: Long,
        val format: Format,
    )

    private val lock = Any()
    private var seq = 0L
    private var prev = ZERO_HASH
    private var expectedLength = 0L
    private var opened = false

    init {
        require(maxBytes in (1L shl 20)..(128L shl 20))
    }

    override fun open(): LedgerHealth = synchronized(lock) {
        var verified = verifyState()
        if (verified.health.ok && verified.format == Format.LEGACY_V2 && protector != null && verified.health.records > 0L) {
            try {
                migrateLegacyLedger()
                verified = verifyState()
            } catch (_: Exception) {
                opened = false
                return@synchronized LedgerHealth(false, verified.health.records, "evidence encryption migration failed")
            }
        }
        if (verified.health.ok) {
            seq = verified.health.records
            prev = verified.lastHash
            expectedLength = verified.length
            opened = true
        } else {
            opened = false
        }
        verified.health
    }

    override fun append(event: EvidenceEvent) = synchronized(lock) {
        validateEvent(event)
        if (!opened) {
            val health = open()
            check(health.ok) { "evidence ledger degraded: ${health.reason}" }
        }
        val actualLength = if (file.exists()) file.length() else 0L
        check(actualLength == expectedLength) { "evidence ledger changed outside writer" }
        if (actualLength >= maxBytes) throw IOException("evidence ledger size limit reached")

        val next = seq + 1
        val bytes = if (protector == null) {
            encodeLegacyLine(next, event, prev)
        } else {
            encodeEncryptedLine(next, event, prev)
        }
        if (actualLength + bytes.size > maxBytes) throw IOException("evidence ledger size limit reached")
        file.parentFile?.let { require(it.mkdirs() || it.isDirectory) }
        FileOutputStream(file, true).use { output ->
            output.write(bytes)
            output.fd.sync()
        }
        val line = bytes.toString(StandardCharsets.UTF_8).trimEnd('\n')
        val mac = line.substringAfterLast('|')
        seq = next
        prev = mac
        expectedLength = actualLength + bytes.size
    }

    /**
     * Atomically re-authenticates an already verified ledger under a new HMAC key.
     *
     * Payload bytes (including encrypted v3 records) are preserved exactly; only the independent
     * HMAC chain is rebuilt. The source ledger must verify under the current key before migration.
     */
    fun rotateAuthenticationKey(newKey: SecretKey): LedgerHealth = synchronized(lock) {
        val verified = verifyState()
        if (!verified.health.ok) return@synchronized verified.health
        if (!file.exists() || verified.health.records == 0L) return@synchronized verified.health

        val parent = file.parentFile ?: return@synchronized LedgerHealth(false, verified.health.records, "evidence parent missing")
        if (!(parent.mkdirs() || parent.isDirectory)) {
            return@synchronized LedgerHealth(false, verified.health.records, "evidence parent unavailable")
        }
        val temp = Files.createTempFile(parent.toPath(), ".${file.name}.rekey-", ".tmp").toFile()
        var previous = ZERO_HASH
        var records = 0L
        try {
            FileOutputStream(temp, false).use { output ->
                boundedLines(file, MAX_LINE_BYTES) { line ->
                    val fields = line.split('|')
                    val body = when {
                        fields.firstOrNull() == RECORD_VERSION_V3 && fields.size == 6 ->
                            listOf(fields[0], fields[1], fields[2], fields[3], previous).joinToString("|")
                        fields.size == 8 ->
                            listOf(fields[0], fields[1], fields[2], fields[3], fields[4], fields[5], previous).joinToString("|")
                        else -> throw IOException("evidence rekey format mismatch")
                    }
                    val nextMac = hmacWithKey(newKey, body)
                    output.write("$body|$nextMac\n".toByteArray(StandardCharsets.UTF_8))
                    previous = nextMac
                    records++
                    if (temp.length() > maxBytes) throw IOException("evidence rekey exceeds size limit")
                }
                output.fd.sync()
            }
            val candidateHealth = EvidenceLedger(temp, newKey, maxBytes, protector).verify()
            if (!candidateHealth.ok || candidateHealth.records != records) {
                return@synchronized LedgerHealth(false, records, "evidence rekey verification failed")
            }
            DurableAtomicFiles.replace(temp, file)
            opened = false
            candidateHealth
        } catch (_: Exception) {
            LedgerHealth(false, records, "evidence rekey failed")
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    override fun verify(): LedgerHealth = synchronized(lock) {
        val verified = verifyState()
        if (verified.health.ok) {
            seq = verified.health.records
            prev = verified.lastHash
            expectedLength = verified.length
            opened = true
        } else {
            opened = false
        }
        verified.health
    }

    override fun recover(archiveDir: File, reason: String): RecoveryResult = synchronized(lock) {
        require(reason.trim().length in 8..512)
        val verified = verifyState()
        require(!verified.health.ok) { "recovery refused: ledger is healthy" }
        require(archiveDir.mkdirs() || archiveDir.isDirectory)
        val suffix = ByteArray(8).also { SecureRandom().nextBytes(it) }.joinToString("") { byte -> "%02x".format(byte) }
        val stem = "evidence-${System.currentTimeMillis()}-$suffix"
        val archive = File(archiveDir, "$stem.log")
        Files.copy(file.toPath(), archive.toPath())
        FileOutputStream(archive, true).use { it.fd.sync() }
        val hash = sha256(archive)
        if (hash != sha256(file)) throw IOException("evidence archive verification failed")
        val manifest = File(archiveDir, "$stem.manifest")
        val payload = listOf(
            "version=3",
            "created=${Instant.now()}",
            "archive=${archive.name}",
            "sha256=$hash",
            "size=${archive.length()}",
            "reason_b64=${b64(reason.trim())}",
            "invalid_line=${verified.health.invalidLine ?: 0}",
        ).joinToString("\n", postfix = "\n")
        val text = payload + "mac=${hmac(payload)}\n"
        FileOutputStream(manifest).use { output ->
            output.write(text.toByteArray(StandardCharsets.UTF_8))
            output.fd.sync()
        }
        if (!verifyRecoveryArchive(manifest).ok) throw IOException("recovery archive manifest verification failed")

        val parent = file.parentFile ?: throw IOException("evidence parent missing")
        require(parent.mkdirs() || parent.isDirectory)
        val temp = Files.createTempFile(parent.toPath(), ".${file.name}.new-", ".tmp").toFile()
        FileOutputStream(temp, false).use { it.fd.sync() }
        val stagedFresh = EvidenceLedger(temp, key, maxBytes, protector).verify()
        if (!stagedFresh.ok || stagedFresh.records != 0L) {
            temp.delete()
            throw IOException("fresh evidence candidate verification failed")
        }
        DurableAtomicFiles.replace(temp, file)

        val fresh = verifyState()
        if (!fresh.health.ok || fresh.health.records != 0L) {
            opened = false
            throw IOException("fresh evidence ledger verification failed")
        }
        seq = 0
        prev = ZERO_HASH
        expectedLength = fresh.length
        opened = true
        RecoveryResult(archive, manifest, hash)
    }

    override fun verifyRecoveryArchive(manifest: File): RecoveryArchiveHealth = synchronized(lock) {
        if (!manifest.isFile || manifest.length() !in 1..MAX_RECOVERY_MANIFEST_BYTES) {
            return@synchronized RecoveryArchiveHealth(false, "manifest missing or oversized")
        }
        val lines = try {
            manifest.readLines(StandardCharsets.UTF_8)
        } catch (_: IOException) {
            return@synchronized RecoveryArchiveHealth(false, "manifest read failed")
        }
        if (lines.size != 8) return@synchronized RecoveryArchiveHealth(false, "manifest field count invalid")
        val fields = LinkedHashMap<String, String>()
        for (line in lines) {
            val index = line.indexOf('=')
            if (index <= 0) return@synchronized RecoveryArchiveHealth(false, "manifest field invalid")
            val key = line.substring(0, index)
            if (fields.put(key, line.substring(index + 1)) != null) {
                return@synchronized RecoveryArchiveHealth(false, "manifest duplicate field")
            }
        }
        if (fields.keys != linkedSetOf("version", "created", "archive", "sha256", "size", "reason_b64", "invalid_line", "mac")) {
            return@synchronized RecoveryArchiveHealth(false, "manifest schema invalid")
        }
        if (fields["version"] !in setOf("2", "3")) return@synchronized RecoveryArchiveHealth(false, "manifest version invalid")
        val name = fields["archive"] ?: return@synchronized RecoveryArchiveHealth(false, "archive name missing")
        if (name.contains('/') || name.contains('\\') || name.startsWith('.')) return@synchronized RecoveryArchiveHealth(false, "archive name invalid")
        val expectedHash = fields["sha256"] ?: return@synchronized RecoveryArchiveHealth(false, "archive hash missing")
        if (!expectedHash.matches(HEX_64)) return@synchronized RecoveryArchiveHealth(false, "archive hash invalid")
        val expectedSize = fields["size"]?.toLongOrNull() ?: return@synchronized RecoveryArchiveHealth(false, "archive size invalid")
        if (expectedSize < 0 || expectedSize > maxBytes) return@synchronized RecoveryArchiveHealth(false, "archive size out of bounds")
        val invalidLine = fields["invalid_line"]?.toLongOrNull() ?: return@synchronized RecoveryArchiveHealth(false, "invalid line invalid")
        if (invalidLine < 0) return@synchronized RecoveryArchiveHealth(false, "invalid line out of bounds")
        try {
            Instant.parse(fields["created"])
        } catch (_: Exception) {
            return@synchronized RecoveryArchiveHealth(false, "created timestamp invalid")
        }
        try {
            Base64.getUrlDecoder().decode(fields["reason_b64"])
        } catch (_: IllegalArgumentException) {
            return@synchronized RecoveryArchiveHealth(false, "reason encoding invalid")
        }
        val macValue = fields["mac"] ?: return@synchronized RecoveryArchiveHealth(false, "manifest MAC missing")
        if (!macValue.matches(HEX_64)) return@synchronized RecoveryArchiveHealth(false, "manifest MAC invalid")
        val payload = lines.take(7).joinToString("\n", postfix = "\n")
        val actualMac = hmac(payload)
        if (!MessageDigest.isEqual(actualMac.toByteArray(StandardCharsets.US_ASCII), macValue.toByteArray(StandardCharsets.US_ASCII))) {
            return@synchronized RecoveryArchiveHealth(false, "manifest authentication failed")
        }
        val archive = File(manifest.parentFile, name)
        if (!archive.isFile || archive.length() != expectedSize) return@synchronized RecoveryArchiveHealth(false, "archive file mismatch")
        val actualHash = try {
            sha256(archive)
        } catch (_: IOException) {
            return@synchronized RecoveryArchiveHealth(false, "archive read failed")
        }
        if (!MessageDigest.isEqual(actualHash.toByteArray(StandardCharsets.US_ASCII), expectedHash.toByteArray(StandardCharsets.US_ASCII))) {
            return@synchronized RecoveryArchiveHealth(false, "archive hash mismatch")
        }
        RecoveryArchiveHealth(true)
    }

    private fun verifyState(): VerifyState {
        if (!file.exists()) return VerifyState(LedgerHealth(true, 0), ZERO_HASH, 0, Format.EMPTY)
        val length = file.length()
        if (length > maxBytes) return VerifyState(LedgerHealth(false, 0, "ledger exceeds size limit"), ZERO_HASH, length, Format.EMPTY)
        var expectedSeq = 1L
        var previous = ZERO_HASH
        var lineNo = 0L
        var detectedFormat = Format.EMPTY
        try {
            boundedLines(file, MAX_LINE_BYTES) { line ->
                lineNo++
                val parsed = verifyLine(line, expectedSeq, previous, lineNo)
                if (detectedFormat == Format.EMPTY) detectedFormat = parsed.first
                else if (detectedFormat != parsed.first) throw LedgerInvalid("mixed ledger formats", lineNo)
                previous = parsed.second
                expectedSeq++
            }
        } catch (error: LedgerInvalid) {
            return VerifyState(LedgerHealth(false, expectedSeq - 1, error.message, error.line), previous, length, detectedFormat)
        } catch (_: LineTooLong) {
            return VerifyState(LedgerHealth(false, expectedSeq - 1, "line exceeds limit", lineNo + 1), previous, length, detectedFormat)
        } catch (_: IOException) {
            return VerifyState(LedgerHealth(false, expectedSeq - 1, "ledger read failed", lineNo + 1), previous, length, detectedFormat)
        }
        return VerifyState(LedgerHealth(true, expectedSeq - 1), previous, length, detectedFormat)
    }

    private fun verifyLine(line: String, expectedSeq: Long, previous: String, lineNo: Long): Pair<Format, String> {
        val fields = line.split('|')
        return if (fields.firstOrNull() == RECORD_VERSION_V3) {
            if (fields.size != 6) throw LedgerInvalid("invalid encrypted field count", lineNo)
            val sequence = fields[1].toLongOrNull() ?: throw LedgerInvalid("invalid sequence", lineNo)
            val atMillis = fields[2].toLongOrNull() ?: throw LedgerInvalid("invalid timestamp", lineNo)
            if (sequence != expectedSeq || fields[4] != previous) throw LedgerInvalid("chain mismatch", lineNo)
            val body = fields.subList(0, 5).joinToString("|")
            val actualMac = hmac(body)
            if (!constantEquals(actualMac, fields[5])) throw LedgerInvalid("authentication failed", lineNo)
            val activeProtector = protector ?: throw LedgerInvalid("encrypted ledger protector unavailable", lineNo)
            val protectedBytes = decodeB64(fields[3], lineNo)
            val plaintext = try {
                activeProtector.unprotect(sequence, atMillis, protectedBytes)
            } catch (_: Exception) {
                throw LedgerInvalid("evidence decryption failed", lineNo)
            } finally {
                protectedBytes.fill(0)
            }
            try {
                val event = decodeEvent(plaintext, lineNo)
                if (event.atMillis != atMillis) throw LedgerInvalid("evidence timestamp mismatch", lineNo)
            } finally {
                plaintext.fill(0)
            }
            Format.ENCRYPTED_V3 to fields[5]
        } else {
            if (fields.size != 8) throw LedgerInvalid("invalid field count", lineNo)
            val sequence = fields[0].toLongOrNull() ?: throw LedgerInvalid("invalid sequence", lineNo)
            if (sequence != expectedSeq || fields[6] != previous) throw LedgerInvalid("chain mismatch", lineNo)
            val body = fields.subList(0, 7).joinToString("|")
            val actualMac = hmac(body)
            if (!constantEquals(actualMac, fields[7])) throw LedgerInvalid("authentication failed", lineNo)
            decodeLegacyEvent(fields, lineNo) // validates all legacy fields before migration/use.
            Format.LEGACY_V2 to fields[7]
        }
    }

    private fun migrateLegacyLedger() {
        val activeProtector = protector ?: return
        val parent = file.parentFile ?: throw IOException("evidence parent missing")
        require(parent.mkdirs() || parent.isDirectory)
        val temp = Files.createTempFile(parent.toPath(), ".${file.name}.enc-", ".tmp").toFile()
        var previous = ZERO_HASH
        var expectedSeq = 1L
        try {
            FileOutputStream(temp, false).use { output ->
                boundedLines(file, MAX_LINE_BYTES) { line ->
                    val fields = line.split('|')
                    if (fields.size != 8 || fields.firstOrNull() == RECORD_VERSION_V3) throw IOException("legacy evidence migration format mismatch")
                    val sequence = fields[0].toLongOrNull() ?: throw IOException("legacy evidence sequence invalid")
                    if (sequence != expectedSeq || fields[6] != previous) throw IOException("legacy evidence chain mismatch")
                    val body = fields.subList(0, 7).joinToString("|")
                    if (!constantEquals(hmac(body), fields[7])) throw IOException("legacy evidence authentication failed")
                    val event = decodeLegacyEvent(fields, expectedSeq)
                    val encrypted = encodeEncryptedLine(sequence, event, previous, activeProtector)
                    output.write(encrypted)
                    previous = encrypted.toString(StandardCharsets.UTF_8).trimEnd('\n').substringAfterLast('|')
                    expectedSeq++
                    if (temp.length() > maxBytes) throw IOException("encrypted evidence migration exceeds size limit")
                }
                output.fd.sync()
            }
            val candidate = EvidenceLedger(temp, key, maxBytes, activeProtector).verify()
            if (!candidate.ok || candidate.records != expectedSeq - 1L) {
                throw IOException("encrypted evidence migration verification failed")
            }
            DurableAtomicFiles.replace(temp, file)
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private fun encodeLegacyLine(sequence: Long, event: EvidenceEvent, previous: String): ByteArray {
        val body = listOf(
            sequence.toString(),
            event.atMillis.toString(),
            b64(event.type),
            b64(event.severity),
            b64(event.subject),
            b64(event.detail),
            previous,
        ).joinToString("|")
        return "$body|${hmac(body)}\n".toByteArray(StandardCharsets.UTF_8)
    }

    private fun encodeEncryptedLine(
        sequence: Long,
        event: EvidenceEvent,
        previous: String,
        explicitProtector: EvidencePayloadProtector? = protector,
    ): ByteArray {
        val activeProtector = explicitProtector ?: throw IOException("evidence protector unavailable")
        val plaintext = encodeEvent(event)
        val protectedPayload = try {
            activeProtector.protect(sequence, event.atMillis, plaintext)
        } finally {
            plaintext.fill(0)
        }
        return try {
            val body = listOf(
                RECORD_VERSION_V3,
                sequence.toString(),
                event.atMillis.toString(),
                Base64.getUrlEncoder().withoutPadding().encodeToString(protectedPayload),
                previous,
            ).joinToString("|")
            "$body|${hmac(body)}\n".toByteArray(StandardCharsets.UTF_8)
        } finally {
            protectedPayload.fill(0)
        }
    }

    private fun encodeEvent(event: EvidenceEvent): ByteArray {
        validateEvent(event)
        return ByteArrayOutputStream(256).use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(EVENT_MAGIC)
                output.writeLong(event.atMillis)
                writeString(output, event.type, MAX_TYPE_BYTES)
                writeString(output, event.severity, MAX_SEVERITY_BYTES)
                writeString(output, event.subject, MAX_SUBJECT_BYTES)
                writeString(output, event.detail, MAX_DETAIL_BYTES)
                output.flush()
            }
            bytes.toByteArray()
        }
    }

    private fun decodeEvent(payload: ByteArray, lineNo: Long): EvidenceEvent {
        if (payload.size !in EVENT_MIN_BYTES..MAX_EVENT_PLAINTEXT_BYTES) throw LedgerInvalid("evidence payload size invalid", lineNo)
        try {
            DataInputStream(ByteArrayInputStream(payload)).use { input ->
                val eventMagic = ByteArray(EVENT_MAGIC.size).also(input::readFully)
                if (!MessageDigest.isEqual(eventMagic, EVENT_MAGIC)) throw LedgerInvalid("evidence payload magic mismatch", lineNo)
                val atMillis = input.readLong()
                val event = EvidenceEvent(
                    type = readString(input, MAX_TYPE_BYTES),
                    severity = readString(input, MAX_SEVERITY_BYTES),
                    subject = readString(input, MAX_SUBJECT_BYTES),
                    detail = readString(input, MAX_DETAIL_BYTES),
                    atMillis = atMillis,
                )
                if (input.read() != -1) throw LedgerInvalid("evidence payload trailing bytes", lineNo)
                validateEvent(event)
                return event
            }
        } catch (error: LedgerInvalid) {
            throw error
        } catch (_: Exception) {
            throw LedgerInvalid("evidence payload decode failed", lineNo)
        }
    }

    private fun decodeLegacyEvent(fields: List<String>, lineNo: Long): EvidenceEvent {
        try {
            val event = EvidenceEvent(
                type = String(Base64.getUrlDecoder().decode(fields[2]), StandardCharsets.UTF_8),
                severity = String(Base64.getUrlDecoder().decode(fields[3]), StandardCharsets.UTF_8),
                subject = String(Base64.getUrlDecoder().decode(fields[4]), StandardCharsets.UTF_8),
                detail = String(Base64.getUrlDecoder().decode(fields[5]), StandardCharsets.UTF_8),
                atMillis = fields[1].toLongOrNull() ?: throw LedgerInvalid("invalid timestamp", lineNo),
            )
            validateEvent(event)
            return event
        } catch (error: LedgerInvalid) {
            throw error
        } catch (_: Exception) {
            throw LedgerInvalid("legacy evidence payload invalid", lineNo)
        }
    }

    private fun validateEvent(event: EvidenceEvent) {
        require(event.type.length in 1..80)
        require(event.severity.length in 1..24)
        require(event.subject.length <= 256)
        require(event.detail.length <= 2048)
        require(event.atMillis > 0L)
    }

    private fun writeString(output: DataOutputStream, value: String, maxBytes: Int) {
        val bytes = value.toByteArray(StandardCharsets.UTF_8)
        require(bytes.size <= maxBytes)
        output.writeInt(bytes.size)
        output.write(bytes)
    }

    private fun readString(input: DataInputStream, maxBytes: Int): String {
        val length = input.readInt()
        if (length !in 0..maxBytes) throw IOException("evidence string length invalid")
        val bytes = ByteArray(length).also(input::readFully)
        return bytes.toString(StandardCharsets.UTF_8)
    }

    private fun decodeB64(value: String, lineNo: Long): ByteArray = try {
        Base64.getUrlDecoder().decode(value)
    } catch (_: IllegalArgumentException) {
        throw LedgerInvalid("evidence encoding invalid", lineNo)
    }

    private fun constantEquals(left: String, right: String): Boolean = MessageDigest.isEqual(
        left.toByteArray(StandardCharsets.US_ASCII),
        right.toByteArray(StandardCharsets.US_ASCII),
    )

    private class LedgerInvalid(message: String, val line: Long) : IOException(message)
    private class LineTooLong : IOException()

    private fun boundedLines(source: File, maxLine: Int, accept: (String) -> Unit) {
        BufferedInputStream(FileInputStream(source), 8192).use { input ->
            val line = ByteArrayOutputStream(minOf(maxLine, 512))
            while (true) {
                val value = input.read()
                if (value < 0) {
                    if (line.size() > 0) accept(line.toString(StandardCharsets.UTF_8.name()))
                    break
                }
                if (value == 10) {
                    accept(line.toString(StandardCharsets.UTF_8.name()))
                    line.reset()
                    continue
                }
                if (value != 13) {
                    if (line.size() >= maxLine) throw LineTooLong()
                    line.write(value)
                }
            }
        }
    }

    private fun hmac(body: String): String = hmacWithKey(key, body)

    private fun hmacWithKey(activeKey: SecretKey, body: String): String =
        hex(BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.doFinal(body.toByteArray(StandardCharsets.UTF_8))
        })

    companion object {
        private const val RECORD_VERSION_V3 = "3"
        private const val ZERO_HASH = "0000000000000000000000000000000000000000000000000000000000000000"
        private const val MAX_RECOVERY_MANIFEST_BYTES = 8192L
        private const val MAX_LINE_BYTES = 24 * 1024
        private const val MAX_TYPE_BYTES = 320
        private const val MAX_SEVERITY_BYTES = 96
        private const val MAX_SUBJECT_BYTES = 1024
        private const val MAX_DETAIL_BYTES = 8192
        private const val MAX_EVENT_PLAINTEXT_BYTES = 12 * 1024
        private val EVENT_MAGIC = "VGTEVT01".toByteArray(StandardCharsets.US_ASCII)
        private val EVENT_MIN_BYTES = EVENT_MAGIC.size + 8 + (4 * 4)
        private val HEX_64 = Regex("[0-9a-f]{64}")

        private fun b64(value: String): String = Base64.getUrlEncoder().withoutPadding()
            .encodeToString(value.toByteArray(StandardCharsets.UTF_8))

        private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

        private fun sha256(file: File): String {
            val digest = MessageDigest.getInstance("SHA-256")
            FileInputStream(file).use { input ->
                val buffer = ByteArray(8192)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    digest.update(buffer, 0, read)
                }
            }
            return hex(digest.digest())
        }
    }
}
