package de.visiongaia.gedefense.tv.core.titan.model

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef

/** Result of comparing one filesystem entry against the persisted FIM baseline. */
enum class FimStatus {
    /** Path is part of the freshly created baseline; no previous state existed. */
    BASELINE_CREATED,
    MATCHES_BASELINE,
    NEW_FILE,
    MODIFIED,
    /** The entry could not be read/hashed at the confirmed privilege level. */
    UNREADABLE,
}

/** A directory tree the Anti-Planting engine watches. Paths are absolute and fixed by the product. */
data class FimWatchRoot(
    val path: String,
    val recursive: Boolean,
    val maxDepth: Int,
) {
    init {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid FIM watch root: $path" }
        require(maxDepth in 0..MAX_DEPTH) { "invalid FIM depth" }
    }

    companion object {
        const val MAX_DEPTH = 6
    }
}

/** Fixed watch policy of the Titan Anti-Planting engine. Never user-configurable at runtime. */
object TitanFimPolicy {
    const val VAULT_PATH = "/data/local/gedefense_vault"

    /**
     * Characters that may never appear in a path handled by the Titan shell/vault layer.
     *
     * Declared before [DEFAULT_ROOTS] on purpose: watch-root validation runs during this object's
     * initialization, so the field must already be assigned when [isSafeAbsolutePath] is called.
     */
    private val SAFE_PATH_FORBIDDEN = setOf(';', '&', '|', '$', '`', '"', '\'', '\\', '<', '>', '*', '?', '!', '(', ')', '{', '}', '[', ']')

    /** Persistent planting locations on Android TV / TV boxes. */
    val DEFAULT_ROOTS: List<FimWatchRoot> = listOf(
        FimWatchRoot("/data/local/tmp", recursive = true, maxDepth = 2),
        FimWatchRoot("/system/bin", recursive = false, maxDepth = 1),
        FimWatchRoot("/system/xbin", recursive = false, maxDepth = 1),
        FimWatchRoot("/vendor/bin", recursive = false, maxDepth = 1),
        FimWatchRoot("/system/etc/init", recursive = false, maxDepth = 1),
        FimWatchRoot("/data/adb/modules", recursive = true, maxDepth = 3),
    )

    /** True when [path] is a watched location (used to bound quarantine source paths). */
    fun isWatched(path: String): Boolean = DEFAULT_ROOTS.any { root ->
        path == root.path || path.startsWith(root.path + "/")
    }

    /** Absolute, no "..", no control characters, bounded length. */
    fun isSafeAbsolutePath(path: String): Boolean {
        if (path.length !in 1..512) return false
        if (!path.startsWith("/") || path.contains("..")) return false
        return path.all { character ->
            character.code in 0x21..0x7e && character !in SAFE_PATH_FORBIDDEN
        }
    }
}

/**
 * One filesystem entry as observed by the platform collector.
 *
 * The core engine never touches the filesystem: the platform hashes readable files and passes the
 * result in. [sha256] is null exactly when [status] is [FimStatus.UNREADABLE].
 */
data class FimFileObservation(
    val path: String,
    val sha256: String?,
    val sizeBytes: Long,
    val modifiedAtMillis: Long,
    val permissions: String?,
    val status: FimStatus,
    val watchedRoot: String,
) {
    init {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid FIM path" }
        require(TitanFimPolicy.isSafeAbsolutePath(watchedRoot)) { "invalid FIM root" }
        require(sizeBytes >= 0L) { "negative FIM size" }
        require(modifiedAtMillis >= 0L) { "invalid FIM timestamp" }
        require(status != FimStatus.UNREADABLE || sha256 == null) { "unreadable FIM entry must not carry a hash" }
        require(sha256 == null || sha256.matches(SHA256_PATTERN)) { "invalid FIM hash" }
        require(permissions == null || permissions.matches(PERMISSION_PATTERN)) { "invalid FIM permissions" }
    }

    companion object {
        private val SHA256_PATTERN = Regex("[0-9a-f]{64}")
        private val PERMISSION_PATTERN = Regex("[0-7]{3,4}")
    }
}

/**
 * One file as read by the platform walker before classification.
 *
 * The platform only reports what it could actually read: [readable] is false when the path could not
 * be opened/listed/hashed, in which case [sha256] must be null. The [FimEngine] turns these entries
 * into [FimFileObservation]s with an explicit [FimStatus].
 */
data class FimScannedFile(
    val path: String,
    val sha256: String?,
    val sizeBytes: Long,
    val modifiedAtMillis: Long,
    val permissions: String?,
    val watchedRoot: String,
    val readable: Boolean,
) {
    init {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid scanned path" }
        require(TitanFimPolicy.isSafeAbsolutePath(watchedRoot)) { "invalid scanned root" }
        require(sizeBytes >= 0L) { "negative scanned size" }
        require(modifiedAtMillis >= 0L) { "invalid scanned timestamp" }
        require(!readable || sha256 != null) { "readable scanned file requires a hash" }
        require(sha256 == null || sha256.matches(Regex("[0-9a-f]{64}"))) { "invalid scanned hash" }
        require(permissions == null || permissions.matches(Regex("[0-7]{3,4}"))) { "invalid scanned permissions" }
    }
}

/** Persisted baseline entry: the trusted "first seen" state of one path. */
data class FimBaselineEntry(
    val path: String,
    val sha256: String,
    val sizeBytes: Long,
    val modifiedAtMillis: Long,
    val permissions: String?,
) {
    init {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid baseline path" }
        require(sha256.matches(Regex("[0-9a-f]{64}"))) { "invalid baseline hash" }
        require(sizeBytes >= 0L) { "negative baseline size" }
        require(modifiedAtMillis >= 0L) { "invalid baseline timestamp" }
    }
}

/** Bounded baseline snapshot (persisted by the platform store). */
data class FimBaseline(
    val entries: List<FimBaselineEntry>,
    val createdAtMillis: Long,
) {
    init {
        require(createdAtMillis > 0L) { "invalid baseline timestamp" }
        require(entries.size <= MAX_ENTRIES) { "baseline too large" }
        require(entries.map { it.path }.distinct().size == entries.size) { "duplicate baseline path" }
    }

    fun byPath(): Map<String, FimBaselineEntry> = entries.associateBy { it.path }

    companion object {
        const val MAX_ENTRIES = 4_096
    }
}

/** Bounded result of one FIM pass. */
data class FimSnapshot(
    val observations: List<FimFileObservation>,
    val baselineCreated: Boolean,
    val newFiles: Int,
    val modifiedFiles: Int,
    val unreadableFiles: Int,
    val scannedFiles: Int,
    val capturedAtMillis: Long,
    val visibility: DataVisibility,
    val truncated: Boolean = false,
    val baselineAtMillis: Long? = null,
    val note: MessageRef? = null,
) {
    init {
        require(newFiles >= 0 && modifiedFiles >= 0 && unreadableFiles >= 0 && scannedFiles >= 0) {
            "negative FIM counters"
        }
        require(observations.size <= MAX_OBSERVATIONS) { "too many FIM observations" }
        require(capturedAtMillis > 0L) { "invalid FIM timestamp" }
        require(baselineAtMillis == null || baselineAtMillis > 0L) { "invalid FIM baseline timestamp" }
    }

    val deltaCount: Int get() = newFiles + modifiedFiles

    companion object {
        const val MAX_OBSERVATIONS = 512

        fun empty(nowMillis: Long, visibility: DataVisibility, note: MessageRef? = null): FimSnapshot =
            FimSnapshot(
                observations = emptyList(),
                baselineCreated = false,
                newFiles = 0,
                modifiedFiles = 0,
                unreadableFiles = 0,
                scannedFiles = 0,
                capturedAtMillis = nowMillis.coerceAtLeast(1L),
                visibility = visibility,
                note = note,
            )
    }
}

/** Hard bounds for one FIM pass; the platform walker may never exceed them. */
data class FimConfig(
    val maxFilesPerRoot: Int = 512,
    val maxTotalFiles: Int = 2_048,
    val maxHashBytes: Long = 64L * 1024L * 1024L,
    val roots: List<FimWatchRoot> = TitanFimPolicy.DEFAULT_ROOTS,
) {
    init {
        require(maxFilesPerRoot in 1..2_048) { "invalid FIM per-root cap" }
        require(maxTotalFiles in 1..4_096) { "invalid FIM total cap" }
        require(maxHashBytes in 1L..(256L * 1024L * 1024L)) { "invalid FIM hash cap" }
        require(roots.isNotEmpty() && roots.size <= 32) { "invalid FIM root count" }
    }

    companion object {
        val DEFAULT = FimConfig()
    }
}
