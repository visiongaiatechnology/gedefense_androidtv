package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.tv.core.titan.model.FimBaseline
import de.visiongaia.gedefense.tv.core.titan.model.FimBaselineEntry
import de.visiongaia.gedefense.tv.core.titan.model.TitanFimPolicy

/**
 * Pure, deterministic text format of the persisted FIM baseline.
 *
 * Layout: one header line `GD-FIM-BASELINE-1|createdAtMillis` followed by one record per line
 * `path|sha256|sizeBytes|modifiedAtMillis|permissions`. FIM paths can never contain `|`
 * ([TitanFimPolicy.isSafeAbsolutePath]), so the separator is unambiguous and no JSON/escaping layer is
 * needed. The format object is deliberately free of Android types so it can be verified on the JVM.
 *
 * Size discipline: a baseline that would exceed [MAX_ENCODED_CHARS] is not encoded at all. A partially
 * written baseline would fabricate `NEW_FILE` deltas on the next comparison, which is worse than
 * comparing against the previous complete baseline again.
 */
internal object TitanFimBaselineFormat {
    const val HEADER = "GD-FIM-BASELINE-1"
    const val MAX_ENCODED_CHARS = 1_048_576

    private val SHA256_PATTERN = Regex("[0-9a-f]{64}")
    private val PERMISSION_PATTERN = Regex("[0-7]{3,4}")

    /** Encodes a complete baseline (sorted, capped) or `null` when it would exceed the char cap. */
    fun encode(baseline: FimBaseline): String? {
        val ordered = baseline.entries.sortedBy { it.path }.take(FimBaseline.MAX_ENTRIES)
        val builder = StringBuilder(minOf(ordered.size * 128, MAX_ENCODED_CHARS))
        builder.append(HEADER).append('|').append(baseline.createdAtMillis.coerceAtLeast(1L)).append('\n')
        for (entry in ordered) {
            val line = entry.path + '|' + entry.sha256 + '|' + entry.sizeBytes + '|' +
                entry.modifiedAtMillis + '|' + (entry.permissions ?: "")
            if (builder.length + line.length + 1 > MAX_ENCODED_CHARS) return null
            builder.append(line).append('\n')
        }
        return builder.toString()
    }

    /**
     * Parses a persisted baseline. Every row is validated field by field; a row that is malformed,
     * out of range, duplicated or outside the FIM path policy is skipped. `null` when the header is
     * invalid or no row survived - an empty baseline is never invented.
     */
    fun parse(raw: String): FimBaseline? {
        if (raw.length > MAX_ENCODED_CHARS) return null
        var createdAt = 0L
        val entries = ArrayList<FimBaselineEntry>(64)
        val seen = HashSet<String>()
        var index = 0
        for (line in raw.lineSequence()) {
            index++
            if (index > FimBaseline.MAX_ENTRIES + 64) break
            if (index == 1) {
                val header = line.split('|')
                if (header.size != 2 || header[0] != HEADER) return null
                createdAt = header[1].toLongOrNull()?.takeIf { it > 0L } ?: return null
                continue
            }
            if (line.isEmpty() || entries.size >= FimBaseline.MAX_ENTRIES) continue
            val parts = line.split('|')
            if (parts.size != 5) continue
            val path = parts[0]
            val sha = parts[1]
            val size = parts[2].toLongOrNull() ?: continue
            val modifiedAt = parts[3].toLongOrNull() ?: continue
            val permissions = parts[4].ifEmpty { null }
            if (size < 0L || modifiedAt < 0L) continue
            if (!TitanFimPolicy.isSafeAbsolutePath(path)) continue
            if (!SHA256_PATTERN.matches(sha)) continue
            if (permissions != null && !PERMISSION_PATTERN.matches(permissions)) continue
            if (!seen.add(path)) continue
            entries += FimBaselineEntry(path, sha, size, modifiedAt, permissions)
        }
        if (entries.isEmpty()) return null
        return try {
            FimBaseline(entries = entries, createdAtMillis = createdAt)
        } catch (_: IllegalArgumentException) {
            null
        }
    }
}

/**
 * Persistence wrapper of the FIM baseline: format codec plus bounded, fail-soft preferences I/O.
 */
internal class TitanFimBaselineCodec(private val prefs: TitanPrefs) {

    fun save(baseline: FimBaseline) {
        try {
            val text = TitanFimBaselineFormat.encode(baseline) ?: return
            val editor = prefs.editor()
            editor.putInt(KEY_FORMAT, TitanPrefs.FORMAT_VERSION)
            editor.putString(KEY_TEXT, text)
            prefs.commit(editor)
        } catch (_: Throwable) {
            // Fail-soft: the next FIM pass compares against the previous baseline again.
        }
    }

    fun load(): FimBaseline? = try {
        val text = prefs.readString(KEY_TEXT)
        if (prefs.readInt(KEY_FORMAT) != TitanPrefs.FORMAT_VERSION || text == null) {
            null
        } else {
            TitanFimBaselineFormat.parse(text)
        }
    } catch (_: Throwable) {
        null
    }

    private companion object {
        const val KEY_FORMAT = "fim.baseline.format"
        const val KEY_TEXT = "fim.baseline.text"
    }
}
