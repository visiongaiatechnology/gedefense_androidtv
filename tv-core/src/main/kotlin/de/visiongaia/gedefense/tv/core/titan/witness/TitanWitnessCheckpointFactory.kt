package de.visiongaia.gedefense.tv.core.titan.witness

import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

/**
 * Produces and verifies the locally HMAC-authenticated witness checkpoint of the evidence ledger.
 *
 * The construction is a two-step binding:
 *  1. `ledgerDigest` = SHA-256 over the canonical ledger text `GD-WD-1\n` followed by one
 *     `atMillis|type|subject\n` line per row (rows in the given order, at most [MAX_ROWS] rows).
 *  2. `macHex` = HMAC-SHA256 over `GD-TW-1\ndeviceId\nsequence\nissuedAtMillis\nledgerDigestHex`.
 *
 * Verification recomputes both values and compares with [MessageDigest.isEqual] (constant time for
 * equal-length inputs); it is fail-closed: malformed input returns `false`, it never throws and never
 * claims a valid checkpoint.
 *
 * This is the honest alpha stage of the witness protocol: the checkpoint proves the local ledger tail
 * was not rewritten after signing. It does not prove delivery to a second device - no pairing, no
 * transport and no push path exists in this build.
 */
object TitanWitnessCheckpointFactory {

    /** Hard bound of rows covered by one digest/checkpoint. */
    const val MAX_ROWS = 200

    private const val SHA_256 = "SHA-256"
    private const val HMAC_SHA_256 = "HmacSHA256"
    private const val HEX_LENGTH = 64
    private const val MAX_TYPE_LENGTH = 64
    private const val MAX_SUBJECT_LENGTH = 256
    private const val LEDGER_DOMAIN = "GD-WD-1\n"
    private const val CHECKPOINT_DOMAIN = "GD-TW-1\n"
    // Evidence ledger event types are dotted ("tv.event", "scan.completed", "containment.applied").
    private val TYPE_PATTERN = Regex("[a-z][a-z0-9._-]{0,63}")
    private val HEX_64 = Regex("[0-9a-f]{64}")

    /**
     * One row of the local evidence ledger tail.
     *
     * Fields are validated so the canonical text is unambiguous: [type] is a rule/event identifier
     * and [subject] is printable ASCII without line breaks (`|` is allowed and does not create
     * ambiguity because the first two separators are fixed-position).
     */
    data class LedgerRow(val atMillis: Long, val type: String, val subject: String) {
        init {
            require(atMillis >= 0L) { "invalid witness row timestamp" }
            require(type.length <= MAX_TYPE_LENGTH && TYPE_PATTERN.matches(type)) { "invalid witness row type" }
            require(subject.length in 1..MAX_SUBJECT_LENGTH) { "invalid witness row subject length" }
            require(subject.all { character -> character.code in 0x20..0x7e }) {
                "invalid witness row subject character"
            }
        }
    }

    /** SHA-256 of the canonical ledger text; lowercase hex. Rows are bound in the given order. */
    fun ledgerDigest(rows: List<LedgerRow>): String {
        require(rows.size <= MAX_ROWS) { "too many witness ledger rows" }
        val digest = MessageDigest.getInstance(SHA_256)
        digest.update(LEDGER_DOMAIN.toByteArray(StandardCharsets.UTF_8))
        for (row in rows) {
            val canonical = "${row.atMillis}|${row.type}|${row.subject}\n"
            digest.update(canonical.toByteArray(StandardCharsets.UTF_8))
        }
        return hex(digest.digest())
    }

    /**
     * Creates one checkpoint. Every argument is validated before a byte is hashed; an invalid key
     * (for example a non-HMAC provider key) is rejected by the JCE with a security exception.
     */
    fun create(
        deviceId: String,
        sequence: Long,
        issuedAtMillis: Long,
        rows: List<LedgerRow>,
        key: SecretKey,
    ): TitanWitnessCheckpoint {
        validateCheckpointInput(deviceId, sequence, issuedAtMillis, rows)
        val digestHex = ledgerDigest(rows)
        val macHex = macHex(payload(deviceId, sequence, issuedAtMillis, digestHex), key)
        require(digestHex.length == HEX_LENGTH && macHex.length == HEX_LENGTH && HEX_64.matches(macHex)) {
            "invalid witness checkpoint encoding"
        }
        return TitanWitnessCheckpoint(
            sequence = sequence,
            issuedAtMillis = issuedAtMillis,
            ledgerDigestHex = digestHex,
            macHex = macHex,
        )
    }

    /**
     * Verifies a checkpoint against the supplied device id, ledger rows and key.
     *
     * Fail-closed: an invalid device id, too many rows, a malformed checkpoint encoding, a wrong key
     * or an unavailable JCE provider yields `false`. Both comparisons are evaluated (no short-circuit)
     * and use [MessageDigest.isEqual].
     */
    fun verify(
        checkpoint: TitanWitnessCheckpoint,
        deviceId: String,
        rows: List<LedgerRow>,
        key: SecretKey,
    ): Boolean {
        if (!TvEvent.DEVICE_ID_PATTERN.matches(deviceId)) return false
        if (rows.size > MAX_ROWS) return false
        if (!HEX_64.matches(checkpoint.ledgerDigestHex) || !HEX_64.matches(checkpoint.macHex)) return false
        if (checkpoint.sequence < 1L || checkpoint.issuedAtMillis <= 0L) return false
        val recomputedDigest = ledgerDigest(rows)
        val recomputedMac = try {
            macHex(payload(deviceId, checkpoint.sequence, checkpoint.issuedAtMillis, recomputedDigest), key)
        } catch (_: GeneralSecurityException) {
            return false
        } catch (_: IllegalArgumentException) {
            return false
        } catch (_: IllegalStateException) {
            return false
        }
        val digestMatches = MessageDigest.isEqual(
            recomputedDigest.toByteArray(StandardCharsets.UTF_8),
            checkpoint.ledgerDigestHex.toByteArray(StandardCharsets.UTF_8),
        )
        val macMatches = MessageDigest.isEqual(
            recomputedMac.toByteArray(StandardCharsets.UTF_8),
            checkpoint.macHex.toByteArray(StandardCharsets.UTF_8),
        )
        return digestMatches && macMatches
    }

    private fun validateCheckpointInput(
        deviceId: String,
        sequence: Long,
        issuedAtMillis: Long,
        rows: List<LedgerRow>,
    ) {
        require(TvEvent.DEVICE_ID_PATTERN.matches(deviceId)) { "invalid witness device id" }
        require(sequence >= 1L) { "invalid witness sequence" }
        require(issuedAtMillis > 0L) { "invalid witness timestamp" }
        require(rows.size <= MAX_ROWS) { "too many witness ledger rows" }
    }

    private fun payload(deviceId: String, sequence: Long, issuedAtMillis: Long, digestHex: String): String =
        CHECKPOINT_DOMAIN + deviceId + "\n" + sequence + "\n" + issuedAtMillis + "\n" + digestHex

    private fun macHex(payload: String, key: SecretKey): String {
        val mac = Mac.getInstance(HMAC_SHA_256)
        mac.init(key)
        return hex(mac.doFinal(payload.toByteArray(StandardCharsets.UTF_8)))
    }

    private fun hex(bytes: ByteArray): String {
        val text = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val value = byte.toInt() and 0xFF
            text.append(HEX_DIGITS[value ushr 4])
            text.append(HEX_DIGITS[value and 0x0F])
        }
        return text.toString()
    }

    private const val HEX_DIGITS = "0123456789abcdef"
}
