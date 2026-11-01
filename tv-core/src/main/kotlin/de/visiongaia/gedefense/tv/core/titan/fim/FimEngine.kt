package de.visiongaia.gedefense.tv.core.titan.fim

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.FimBaseline
import de.visiongaia.gedefense.tv.core.titan.model.FimBaselineEntry
import de.visiongaia.gedefense.tv.core.titan.model.FimConfig
import de.visiongaia.gedefense.tv.core.titan.model.FimFileObservation
import de.visiongaia.gedefense.tv.core.titan.model.FimScannedFile
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.FimStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys

/**
 * Result of one FIM pass: the bounded snapshot, the baseline to persist and whether it changed.
 *
 * [newBaseline] is never `null` in the current contract - it is the complete baseline after the pass,
 * so the platform can persist it verbatim. The field stays nullable so a future "baseline discard"
 * path cannot silently break callers.
 */
data class FimComparison(
    val snapshot: FimSnapshot,
    val newBaseline: FimBaseline?,
    val baselineChanged: Boolean,
)

/**
 * Anti-planting delta engine over the fixed [FimConfig] watch policy.
 *
 * The engine is pure and deterministic: it never touches the filesystem, never throws on odd input
 * and never invents file facts. The platform walker hashes readable files and passes [FimScannedFile]
 * rows in; the engine classifies them against the persisted [FimBaseline].
 *
 * Deletion is deliberately not claimed: a baseline entry that is absent from a scan is retained in
 * the new baseline ("no deletion detection claim"). Readable files that are new or modified update the
 * baseline; unreadable files never erase an existing baseline entry.
 *
 * All bounds are hard: [FimConfig.maxFilesPerRoot], [FimConfig.maxTotalFiles],
 * [FimBaseline.MAX_ENTRIES] and [FimSnapshot.MAX_OBSERVATIONS]. Any drop sets [FimSnapshot.truncated].
 */
class FimEngine(
    private val config: FimConfig = FimConfig.DEFAULT,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    /**
     * Compares one scan against [baseline] (`null` on the first run, which creates the baseline).
     *
     * @param nowMillis capture time; non-positive values clamp to 1 ms. No other timestamp is derived.
     */
    fun compare(baseline: FimBaseline?, scanned: List<FimScannedFile>, nowMillis: Long): FimComparison {
        val now = nowMillis.coerceAtLeast(1L)
        val bounded = boundScanned(scanned)
        val included = bounded.files
        var truncated = bounded.truncated
        val baselineCreated = baseline == null
        val baselineByPath = baseline?.byPath().orEmpty()
        val previousEntries = baseline?.entries?.sortedBy { entry -> entry.path }.orEmpty()
        val observations = ArrayList<FimFileObservation>(minOf(included.size, FimSnapshot.MAX_OBSERVATIONS))
        var newFiles = 0
        var modifiedFiles = 0
        var unreadableFiles = 0
        for (file in included) {
            val status = classify(file, baselineCreated, baselineByPath)
            when (status) {
                FimStatus.NEW_FILE -> newFiles += 1
                FimStatus.MODIFIED -> modifiedFiles += 1
                FimStatus.UNREADABLE -> unreadableFiles += 1
                FimStatus.BASELINE_CREATED, FimStatus.MATCHES_BASELINE -> Unit
            }
            observations += FimFileObservation(
                path = file.path,
                sha256 = if (file.readable) file.sha256 else null,
                sizeBytes = file.sizeBytes,
                modifiedAtMillis = file.modifiedAtMillis,
                permissions = file.permissions,
                status = status,
                watchedRoot = file.watchedRoot,
            )
        }
        observations.sortWith(OBSERVATION_ORDER)
        val scannedFiles = observations.size
        val capped = if (scannedFiles > FimSnapshot.MAX_OBSERVATIONS) {
            truncated = true
            observations.subList(0, FimSnapshot.MAX_OBSERVATIONS).toList()
        } else {
            observations.toList()
        }
        val visibility = if (unreadableFiles == 0 && scannedFiles > 0) DataVisibility.FULL else DataVisibility.PARTIAL
        val rebuilt = buildBaseline(baseline, included, now)
        if (rebuilt.truncated) truncated = true
        val changed = baselineCreated || rebuilt.baseline.entries != previousEntries
        val note = when {
            baselineCreated -> MessageRef(TitanTextKeys.NOTE_FIM_BASELINE)
            unreadableFiles > 0 -> MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE)
            else -> null
        }
        return FimComparison(
            snapshot = FimSnapshot(
                observations = capped,
                baselineCreated = baselineCreated,
                newFiles = newFiles,
                modifiedFiles = modifiedFiles,
                unreadableFiles = unreadableFiles,
                scannedFiles = scannedFiles,
                capturedAtMillis = now,
                visibility = visibility,
                truncated = truncated,
                baselineAtMillis = baseline?.createdAtMillis ?: now,
                note = note,
            ),
            newBaseline = rebuilt.baseline,
            baselineChanged = changed,
        )
    }

    /** Convenience overload using the injected [clock]; invalid clock values clamp to 1 ms. */
    fun compare(baseline: FimBaseline?, scanned: List<FimScannedFile>): FimComparison =
        compare(baseline, scanned, clock().coerceAtLeast(1L))

    // -------------------------------------------------------------------------------- classification

    private fun classify(
        file: FimScannedFile,
        baselineCreated: Boolean,
        baselineByPath: Map<String, FimBaselineEntry>,
    ): FimStatus {
        if (!file.readable) return FimStatus.UNREADABLE
        if (baselineCreated) return FimStatus.BASELINE_CREATED
        val previous = baselineByPath[file.path] ?: return FimStatus.NEW_FILE
        val unchanged = previous.sha256 == file.sha256 && previous.sizeBytes == file.sizeBytes
        return if (unchanged) FimStatus.MATCHES_BASELINE else FimStatus.MODIFIED
    }

    /**
     * Bounds and normalises the caller's scan: deterministic path order, drop entries outside the
     * configured roots, de-duplicate paths, then apply the per-root and total caps.
     */
    private fun boundScanned(scanned: List<FimScannedFile>): BoundedScan {
        if (scanned.isEmpty()) return BoundedScan(emptyList(), truncated = false)
        val sorted = scanned.sortedWith(compareBy { file -> file.path })
        val rootCounts = HashMap<String, Int>(minOf(config.roots.size * 2, MAX_ROOT_BUCKETS))
        val seenPaths = HashSet<String>(minOf(sorted.size, config.maxTotalFiles * 2))
        val included = ArrayList<FimScannedFile>(minOf(sorted.size, config.maxTotalFiles))
        for (file in sorted) {
            if (included.size >= config.maxTotalFiles) break
            if (!isUnderConfiguredRoot(file)) continue
            if (!seenPaths.add(file.path)) continue
            val rootCount = rootCounts[file.watchedRoot] ?: 0
            if (rootCount >= config.maxFilesPerRoot) continue
            rootCounts[file.watchedRoot] = rootCount + 1
            included += file
        }
        return BoundedScan(included, truncated = included.size < scanned.size)
    }

    private fun isUnderConfiguredRoot(file: FimScannedFile): Boolean {
        val root = config.roots.firstOrNull { candidate -> candidate.path == file.watchedRoot } ?: return false
        return file.path == root.path || file.path.startsWith(root.path + "/")
    }

    // ------------------------------------------------------------------------------------ baseline

    private fun buildBaseline(
        baseline: FimBaseline?,
        included: List<FimScannedFile>,
        nowMillis: Long,
    ): BuiltBaseline {
        if (baseline == null) {
            val readable = included.mapNotNull(::toEntry).sortedBy { entry -> entry.path }
            val capped = capEntries(readable)
            return BuiltBaseline(
                entries = capped,
                baseline = FimBaseline(capped, nowMillis),
                truncated = readable.size > capped.size,
            )
        }
        val merged = LinkedHashMap<String, FimBaselineEntry>(baseline.entries.size * 2)
        baseline.entries.sortedBy { entry -> entry.path }.forEach { entry -> merged[entry.path] = entry }
        for (file in included) {
            val entry = toEntry(file) ?: continue
            merged[entry.path] = entry
        }
        val sorted = merged.values.sortedBy { entry -> entry.path }
        val capped = capEntries(sorted)
        return BuiltBaseline(
            entries = capped,
            baseline = FimBaseline(capped, baseline.createdAtMillis),
            truncated = merged.size > capped.size,
        )
    }

    private fun capEntries(entries: List<FimBaselineEntry>): List<FimBaselineEntry> =
        if (entries.size > FimBaseline.MAX_ENTRIES) entries.subList(0, FimBaseline.MAX_ENTRIES).toList() else entries

    private fun toEntry(file: FimScannedFile): FimBaselineEntry? {
        val hash = file.sha256 ?: return null
        return FimBaselineEntry(
            path = file.path,
            sha256 = hash,
            sizeBytes = file.sizeBytes,
            modifiedAtMillis = file.modifiedAtMillis,
            permissions = file.permissions,
        )
    }

    private data class BoundedScan(val files: List<FimScannedFile>, val truncated: Boolean)

    private data class BuiltBaseline(
        val entries: List<FimBaselineEntry>,
        val baseline: FimBaseline,
        val truncated: Boolean,
    )

    companion object {
        private const val MAX_ROOT_BUCKETS = 64

        /** Delta-first observation order: new/modified, then unreadable, baseline, matches; path last. */
        private val OBSERVATION_ORDER: Comparator<FimFileObservation> = Comparator { first, second ->
            var result = deltaRank(first.status).compareTo(deltaRank(second.status))
            if (result == 0) result = statusRank(first.status).compareTo(statusRank(second.status))
            if (result == 0) result = first.path.compareTo(second.path)
            result
        }

        private fun deltaRank(status: FimStatus): Int = when (status) {
            FimStatus.NEW_FILE, FimStatus.MODIFIED -> 0
            FimStatus.UNREADABLE, FimStatus.BASELINE_CREATED, FimStatus.MATCHES_BASELINE -> 1
        }

        private fun statusRank(status: FimStatus): Int = when (status) {
            FimStatus.NEW_FILE -> 0
            FimStatus.MODIFIED -> 1
            FimStatus.UNREADABLE -> 2
            FimStatus.BASELINE_CREATED -> 3
            FimStatus.MATCHES_BASELINE -> 4
        }
    }
}
