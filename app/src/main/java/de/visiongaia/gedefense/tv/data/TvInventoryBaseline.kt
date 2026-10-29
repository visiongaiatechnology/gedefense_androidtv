package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.InventoryDelta

/**
 * Local app-inventory baseline used for "new/changed since last scan" hints.
 *
 * Only package names and version codes are stored (no labels, no signatures, no permissions), in the
 * app-private preferences file. The baseline is a review hint, never a trust proof, and the store
 * fails soft: an unreadable baseline simply reports [InventoryDelta.baselineAvailable] = false.
 */
class TvInventoryBaseline(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun computeDelta(apps: List<InstalledApp>, nowMillis: Long): InventoryDelta {
        val baseline = load()
        val baselineAtMillis = prefs.getLong(KEY_BASELINE_AT, 0L).coerceAtLeast(0L).takeIf { it > 0L }
        val current = apps.associate { it.packageName to it.versionCode }
        save(current, nowMillis)
        if (baseline == null || baselineAtMillis == null) {
            // Without both the stored map and its timestamp a comparison would be a guess, so the
            // delta is explicitly unavailable instead of invented.
            return InventoryDelta(
                newPackages = emptyList(),
                changedPackages = emptyList(),
                removedPackages = emptyList(),
                baselineAvailable = false,
                baselineAtMillis = null,
            )
        }
        val newPackages = current.keys.filter { it !in baseline }.sorted()
        val changedPackages = current.entries
            .filter { (pkg, version) -> baseline[pkg] != null && baseline[pkg] != version }
            .map { it.key }
            .sorted()
        val removedPackages = baseline.keys.filter { it !in current }.sorted()
        return InventoryDelta(
            newPackages = newPackages,
            changedPackages = changedPackages,
            removedPackages = removedPackages,
            baselineAvailable = true,
            baselineAtMillis = baselineAtMillis,
        )
    }

    private fun load(): Map<String, Long>? {
        val raw = try {
            prefs.getString(KEY_BASELINE, null)
        } catch (_: RuntimeException) {
            null
        } ?: return null
        if (raw.length > MAX_BASELINE_CHARS) return null
        val result = LinkedHashMap<String, Long>()
        for (line in raw.lineSequence()) {
            if (line.isEmpty()) continue
            val index = line.lastIndexOf('|')
            if (index <= 0) continue
            val pkg = line.substring(0, index)
            val version = line.substring(index + 1).toLongOrNull() ?: continue
            if (result.size >= MAX_BASELINE_ENTRIES) break
            result[pkg] = version
        }
        return result
    }

    private fun save(current: Map<String, Long>, nowMillis: Long) {
        val text = buildString {
            var count = 0
            for ((pkg, version) in current) {
                if (count >= MAX_BASELINE_ENTRIES) break
                append(pkg).append('|').append(version).append('\n')
                count++
            }
        }
        try {
            prefs.edit()
                .putString(KEY_BASELINE, text)
                .putLong(KEY_BASELINE_AT, nowMillis.coerceAtLeast(0L))
                .apply()
        } catch (_: RuntimeException) {
            // A failed baseline write must never fail the scan; the next scan starts a new baseline.
        }
    }

    companion object {
        private const val PREFS_NAME = "gedefense_tv_inventory"
        private const val KEY_BASELINE = "baseline.v1"
        private const val KEY_BASELINE_AT = "baseline.at"
        private const val MAX_BASELINE_ENTRIES = 4_000
        private const val MAX_BASELINE_CHARS = 512 * 1024
    }
}
