package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus

/**
 * SharedPreferences access boundary of the Titan persistence layer.
 *
 * Every read treats the preferences file as potentially corrupted or manipulated: type mismatches,
 * missing keys and platform failures yield `null` instead of throwing. Writes go through [commit] so
 * a persistence failure can never escape into a scan or the UI.
 *
 * The preferences file is app-private (`MODE_PRIVATE`) and stores only bounded, non-secret state:
 * capability counters, privilege evidence, FIM baseline hashes (SHA-256 of system files, not file
 * contents), quarantine metadata and witness counters. No live `/proc` rows, no raw shell output and
 * no key material is ever stored here.
 */
internal class TitanPrefs(private val prefs: SharedPreferences) {

    /** Wraps the app-private Titan preferences file of [context]. */
    constructor(context: Context) : this(
        (context.applicationContext ?: context).getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE),
    )

    fun editor(): SharedPreferences.Editor = prefs.edit()

    /** Commits [editor]; a failed/denied write is reported as `false`, never as an exception. */
    fun commit(editor: SharedPreferences.Editor): Boolean = try {
        editor.commit()
    } catch (_: Throwable) {
        false
    }

    fun readString(key: String): String? = try {
        prefs.getString(key, null)
    } catch (_: Throwable) {
        null
    }

    fun readInt(key: String): Int? = if (contains(key)) {
        try {
            prefs.getInt(key, 0)
        } catch (_: Throwable) {
            null
        }
    } else {
        null
    }

    fun readLong(key: String): Long? = if (contains(key)) {
        try {
            prefs.getLong(key, 0L)
        } catch (_: Throwable) {
            null
        }
    } else {
        null
    }

    fun readBoolean(key: String): Boolean? = if (contains(key)) {
        try {
            prefs.getBoolean(key, false)
        } catch (_: Throwable) {
            null
        }
    } else {
        null
    }

    /**
     * Reads a tri-state boolean stored as "1"/"0". Anything else (missing, foreign value, corrupted
     * file) is honestly "unknown" and maps to `null`, never to `false`.
     */
    fun readTriState(key: String): Boolean? = when (readString(key)) {
        TRI_STATE_TRUE -> true
        TRI_STATE_FALSE -> false
        else -> null
    }

    fun putTriState(editor: SharedPreferences.Editor, key: String, value: Boolean?) {
        when (value) {
            true -> editor.putString(key, TRI_STATE_TRUE)
            false -> editor.putString(key, TRI_STATE_FALSE)
            null -> editor.remove(key)
        }
    }

    private fun contains(key: String): Boolean = try {
        prefs.contains(key)
    } catch (_: Throwable) {
        false
    }

    companion object {
        const val PREFS_NAME = "gedefense_tv_titan"

        /** Format version of every persisted Titan block; a mismatch is treated as "not persisted". */
        const val FORMAT_VERSION = 1

        private const val TRI_STATE_TRUE = "1"
        private const val TRI_STATE_FALSE = "0"
    }
}

/**
 * Injection-safe codec for [MessageRef] lists that are persisted together with the Titan state.
 *
 * Encoding is one ref per line: `key|hex(arg0)|hex(arg1)...`. Catalog arguments are hex-encoded, so
 * they can never contain the record separator or a line break - a manipulated preferences file cannot
 * smuggle an extra record into the list. Invalid or oversized refs are dropped instead of being
 * written in a lossy form; decoding never throws.
 */
internal object TitanNoteCodec {
    private const val MAX_ENCODED_CHARS = 32_768
    private const val MAX_ARGS = 8
    private const val MAX_ARG_LENGTH = 512
    private const val MAX_HEX_ARG_CHARS = 4_096
    private const val MAX_NOTES = TitanStatus.MAX_NOTES

    private val KEY_PATTERN = Regex("""[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}""")
    private const val HEX_DIGITS = "0123456789abcdef"

    /** Encodes a bounded list; returns an empty string when no ref is encodable. */
    fun encode(notes: List<MessageRef>): String {
        val builder = StringBuilder()
        for (note in notes.take(MAX_NOTES)) {
            if (!KEY_PATTERN.matches(note.key)) continue
            if (note.args.size > MAX_ARGS || note.args.any { it.length > MAX_ARG_LENGTH }) continue
            val line = StringBuilder(note.key.length + note.args.size * 8)
            line.append(note.key)
            for (arg in note.args) {
                line.append('|').append(hexEncode(arg))
            }
            if (builder.isNotEmpty()) builder.append('\n')
            if (builder.length + line.length > MAX_ENCODED_CHARS) break
            builder.append(line)
        }
        return builder.toString()
    }

    /** Decodes a persisted list; anything malformed is skipped, never thrown. */
    fun decode(raw: String?): List<MessageRef> {
        if (raw == null || raw.length > MAX_ENCODED_CHARS) return emptyList()
        val notes = ArrayList<MessageRef>(4)
        for (line in raw.lineSequence()) {
            if (notes.size >= MAX_NOTES) break
            val note = decodeLine(line) ?: continue
            notes += note
        }
        return notes
    }

    /** Encodes at most one ref (used for module notes); `null` when absent/unencodable. */
    fun encodeSingle(note: MessageRef?): String? {
        if (note == null) return null
        val encoded = encode(listOf(note))
        return encoded.ifEmpty { null }
    }

    fun decodeSingle(raw: String?): MessageRef? {
        if (raw == null || raw.length > MAX_ENCODED_CHARS) return null
        for (line in raw.lineSequence()) {
            decodeLine(line)?.let { return it }
        }
        return null
    }

    private fun decodeLine(line: String): MessageRef? {
        if (line.isEmpty()) return null
        val parts = line.split('|')
        val key = parts[0]
        if (!KEY_PATTERN.matches(key)) return null
        if (parts.size - 1 > MAX_ARGS) return null
        val args = ArrayList<String>(parts.size - 1)
        for (index in 1 until parts.size) {
            val decoded = hexDecode(parts[index]) ?: return null
            args += decoded
        }
        return try {
            MessageRef(key, args)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun hexEncode(value: String): String {
        if (value.isEmpty()) return ""
        val bytes = value.toByteArray(Charsets.UTF_8)
        val builder = StringBuilder(bytes.size * 2)
        for (byte in bytes) {
            val unsigned = byte.toInt() and 0xFF
            builder.append(HEX_DIGITS[unsigned ushr 4]).append(HEX_DIGITS[unsigned and 0x0F])
        }
        return builder.toString()
    }

    private fun hexDecode(encoded: String): String? {
        if (encoded.isEmpty()) return ""
        if (encoded.length % 2 != 0 || encoded.length > MAX_HEX_ARG_CHARS) return null
        val bytes = ByteArray(encoded.length / 2)
        for (index in bytes.indices) {
            val high = hexDigit(encoded[index * 2]) ?: return null
            val low = hexDigit(encoded[index * 2 + 1]) ?: return null
            bytes[index] = ((high shl 4) or low).toByte()
        }
        val decoded = String(bytes, Charsets.UTF_8)
        // A lossy decode (invalid UTF-8) would silently change the argument text: reject it.
        if (!decoded.toByteArray(Charsets.UTF_8).contentEquals(bytes)) return null
        if (decoded.length > MAX_ARG_LENGTH) return null
        return decoded
    }

    private fun hexDigit(character: Char): Int? = when (character) {
        in '0'..'9' -> character - '0'
        in 'a'..'f' -> character - 'a' + 10
        else -> null
    }
}
