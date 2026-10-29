package de.visiongaia.gedefense.mobile.core

import java.io.File
import java.io.IOException
import java.nio.channels.FileChannel
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption

/**
 * Crash-safe same-directory publication for security-sensitive core state.
 *
 * Callers must fully write, flush/fsync and verify the candidate before invoking [replace]. The
 * commit itself never degrades to a non-atomic move: if the filesystem cannot provide atomic rename,
 * publication fails closed and the previous target remains authoritative. The containing directory
 * is fsynced after rename so the directory entry survives a power loss.
 */
object DurableAtomicFiles {
    @Throws(IOException::class)
    fun replace(temp: File, target: File) {
        val parent = target.parentFile ?: throw IOException("atomic target parent missing")
        val parentPath = parent.toPath()
        if (Files.isSymbolicLink(parentPath) || !Files.isDirectory(parentPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("atomic target parent is not a trusted directory")
        }

        val canonicalParent = parent.canonicalFile
        val canonicalTemp = temp.canonicalFile
        if (canonicalTemp.parentFile != canonicalParent) {
            throw IOException("atomic replace requires same directory")
        }
        val tempPath = canonicalTemp.toPath()
        if (Files.isSymbolicLink(tempPath) || !Files.isRegularFile(tempPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("atomic candidate is not a regular file")
        }

        val canonicalTarget = File(canonicalParent, target.name)
        val targetPath = canonicalTarget.toPath()
        if (Files.exists(targetPath, LinkOption.NOFOLLOW_LINKS) &&
            (Files.isSymbolicLink(targetPath) || !Files.isRegularFile(targetPath, LinkOption.NOFOLLOW_LINKS))) {
            throw IOException("atomic target is not a regular file")
        }

        try {
            Files.move(
                tempPath,
                targetPath,
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
        } catch (error: AtomicMoveNotSupportedException) {
            throw IOException("atomic replace unsupported", error)
        }
        fsyncDirectory(parentPath)
    }

    @Throws(IOException::class)
    private fun fsyncDirectory(path: java.nio.file.Path) {
        try {
            FileChannel.open(path, StandardOpenOption.READ).use { channel -> channel.force(true) }
        } catch (error: UnsupportedOperationException) {
            throw IOException("directory fsync unsupported", error)
        } catch (error: SecurityException) {
            throw IOException("directory fsync denied", error)
        }
    }
}
