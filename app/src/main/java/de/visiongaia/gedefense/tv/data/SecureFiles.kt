package de.visiongaia.gedefense.tv.data

import android.system.Os
import android.system.OsConstants
import java.io.File
import java.io.IOException

/**
 * Private, crash-safe file helpers for the TV threat-intel download path.
 *
 * Ported from the GeDefense mobile dossier. The TV app only needs the temp-plus-fsync primitives
 * here; evidence durability is owned by the vendored core ledger.
 */
object SecureFiles {
    private const val PRIVATE_FILE_MODE = 384 // 0600

    fun createPrivateTempFile(directory: File, prefix: String, suffix: String = ".tmp"): File {
        require(prefix.length >= 3 && prefix.length <= 96) { "invalid temp prefix" }
        require(suffix.length in 1..32 && !suffix.contains('/') && !suffix.contains('\\')) { "invalid temp suffix" }
        require(directory.mkdirs() || directory.isDirectory) { "temp directory unavailable" }
        val parent = directory.canonicalFile
        val temp = File.createTempFile(prefix, suffix, parent)
        try {
            val canonical = temp.canonicalFile
            require(canonical.parentFile == parent) { "temp file escaped directory" }
            Os.chmod(canonical.absolutePath, PRIVATE_FILE_MODE)
            return canonical
        } catch (t: Throwable) {
            temp.delete()
            throw t
        }
    }

    fun fsyncDirectory(directory: File) {
        val fd = Os.open(directory.absolutePath, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    /** Deletes test leftovers without ever following symlinks out of the app-private directory. */
    fun deleteQuietly(file: File) {
        try {
            if (!file.exists()) return
            if (file.canonicalFile.parentFile == file.parentFile?.canonicalFile) file.delete()
        } catch (_: IOException) {
            // Best effort only: stale temp cleanup must never affect the sync result.
        }
    }
}
