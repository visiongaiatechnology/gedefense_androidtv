package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry

/**
 * Pure, deterministic text format of the quarantine-vault metadata rows (newest first).
 *
 * Layout: one record per line `id|fileName|originalPath|sha256|sizeBytes|storedAtMillis|permissions`.
 * Both the vault file name (safe character class) and the original path (validated by the Titan FIM
 * policy) can never contain `|`, so no escaping layer is needed. The format object is deliberately
 * free of Android types so it can be verified on the JVM.
 *
 * Every row is re-validated through the [TitanVaultEntry] constructor on load; one corrupt row is
 * skipped, the remaining rows survive. The vault row is metadata only.
 */
internal object TitanVaultFormat {
    const val MAX_ENTRIES = 128
    const val MAX_ENCODED_CHARS = 65_536

    /** Encodes the bounded list; `null` when the encoded text would exceed the char cap. */
    fun encode(entries: List<TitanVaultEntry>): String? {
        val builder = StringBuilder(minOf(entries.size * 160, MAX_ENCODED_CHARS))
        for (entry in entries.take(MAX_ENTRIES)) {
            val line = entry.id + '|' + entry.fileName + '|' + entry.originalPath + '|' +
                entry.sha256 + '|' + entry.sizeBytes + '|' + entry.storedAtMillis + '|' +
                (entry.permissions ?: "")
            if (builder.length + line.length + 1 > MAX_ENCODED_CHARS) return null
            builder.append(line).append('\n')
        }
        return builder.toString()
    }

    /** Parses persisted rows; malformed/duplicate rows are skipped, never thrown. */
    fun parse(raw: String): List<TitanVaultEntry> {
        if (raw.length > MAX_ENCODED_CHARS) return emptyList()
        val entries = ArrayList<TitanVaultEntry>(8)
        val seenIds = HashSet<String>()
        val seenFiles = HashSet<String>()
        for (line in raw.lineSequence()) {
            if (entries.size >= MAX_ENTRIES) break
            if (line.isEmpty()) continue
            val parts = line.split('|')
            if (parts.size != 7) continue
            val size = parts[4].toLongOrNull() ?: continue
            val storedAt = parts[5].toLongOrNull() ?: continue
            val candidate = try {
                TitanVaultEntry(
                    id = parts[0],
                    fileName = parts[1],
                    originalPath = parts[2],
                    sha256 = parts[3],
                    sizeBytes = size,
                    storedAtMillis = storedAt,
                    permissions = parts[6].ifEmpty { null },
                )
            } catch (_: IllegalArgumentException) {
                null
            } ?: continue
            if (!seenIds.add(candidate.id) || !seenFiles.add(candidate.fileName)) continue
            entries += candidate
        }
        return entries
    }
}

/**
 * Persistence wrapper of the vault metadata: format codec plus fail-soft preferences I/O.
 */
internal class TitanVaultCodec(private val prefs: TitanPrefs) {

    fun load(): List<TitanVaultEntry> = try {
        val raw = prefs.readString(KEY_ENTRIES)
        if (raw == null) emptyList() else TitanVaultFormat.parse(raw)
    } catch (_: Throwable) {
        emptyList()
    }

    fun add(entry: TitanVaultEntry) {
        try {
            val existing = load()
            if (existing.any { it.id == entry.id || it.fileName == entry.fileName }) return
            val merged = ArrayList<TitanVaultEntry>(minOf(existing.size + 1, TitanVaultFormat.MAX_ENTRIES))
            merged += entry
            for (previous in existing) {
                if (merged.size >= TitanVaultFormat.MAX_ENTRIES) break
                merged += previous
            }
            val text = TitanVaultFormat.encode(merged) ?: return
            prefs.commit(prefs.editor().putString(KEY_ENTRIES, text))
        } catch (_: Throwable) {
            // Fail-soft: the vault list is a display cache, the quarantined data is not.
        }
    }

    private companion object {
        const val KEY_ENTRIES = "vault.entries"
    }
}
