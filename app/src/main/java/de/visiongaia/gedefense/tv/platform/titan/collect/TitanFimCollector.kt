package de.visiongaia.gedefense.tv.platform.titan.collect

import android.content.Context
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.fim.FimEngine
import de.visiongaia.gedefense.tv.core.titan.model.FimConfig
import de.visiongaia.gedefense.tv.core.titan.model.FimScannedFile
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.FimWatchRoot
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys
import de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory
import de.visiongaia.gedefense.tv.core.titan.response.TitanShellCommand
import de.visiongaia.gedefense.tv.data.TvTitanStore
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanShell

/**
 * Passive FIM (file-integrity-monitoring) collector of the Titan Anti-Planting engine.
 *
 * Honest gating first: without [TitanCapability.DEEP_INVENTORY_FIM] the collector returns an explicit
 * PARTIAL empty snapshot with the FIM-unreadable note, never a clean result. With the capability all
 * filesystem access runs through the confirmed root channel and only allow-listed read-only commands
 * are used: `find` for the fixed watch roots, `stat` for mode/size/mtime and `sha256sum` for the hash.
 * Shell output is hostile input: every path is validated against the FIM path policy and the configured
 * root, output is hard-capped, and a path outside the root is rejected.
 *
 * Coverage discipline (F-01/F-09): the allow-listed watch-root command uses newline-separated
 * `find -print` output, which cannot faithfully represent file names containing line breaks and which
 * the FIM path policy rejects for spaces/glob characters (`?`, `*`, `!`, `()[]{}`, ...). Such lines are
 * not silently dropped: every rejected/unparseable line, a non-zero `find` exit (except a genuinely
 * missing root reported as "No such file or directory") and a possibly capped payload mark the listing
 * as incomplete. An incomplete listing becomes `truncated = true` with PARTIAL visibility and the
 * FIM-unreadable note, so a planted hostile name can never produce a "clean, unchanged tree" claim.
 * A `-print0` variant would be preferable but requires a new allow-listed command in
 * [TitanCommandFactory] (tv-core owner); until then the collector detects and flags instead.
 *
 * Size discipline: a file larger than [FimConfig.maxHashBytes] is reported as unreadable (not hashed,
 * not silently trusted) and the snapshot is marked truncated. The whole pass has a wall-clock budget
 * so a huge or slow tree cannot stall the scan worker.
 *
 * Baseline handling: the previous baseline is loaded from [TvTitanStore], compared by the pure
 * [FimEngine], and a changed baseline is persisted before the snapshot is returned.
 *
 * Threading: [collect] blocks on shell commands and preference I/O and MUST run on a background worker
 * (the TitanController scan executor), never on the UI thread.
 *
 * @param context unused; accepted to keep the platform-collector construction signature uniform.
 * @param shellProvider returns the confirmed shell channel, or `null` when it is unavailable.
 * @param store persistence of the FIM baseline (never used for live rows).
 */
class TitanFimCollector(
    @Suppress("UNUSED_PARAMETER") context: Context,
    private val shellProvider: () -> TitanShell?,
    private val store: TvTitanStore,
) {
    private val engine = FimEngine(config = FimConfig.DEFAULT)

    /**
     * Runs one bounded FIM pass. Never throws; every failure path returns a PARTIAL empty snapshot
     * with the FIM-unreadable note.
     */
    fun collect(privilege: TitanPrivilegeSnapshot, nowMillis: Long): FimSnapshot {
        val now = nowMillis.coerceAtLeast(1L)
        return try {
            collectInternal(privilege, now)
        } catch (_: Throwable) {
            unavailable(now)
        }
    }

    private fun collectInternal(privilege: TitanPrivilegeSnapshot, now: Long): FimSnapshot {
        if (TitanCapability.DEEP_INVENTORY_FIM !in TitanCapabilityMatrix.effectiveCapabilities(privilege)) {
            return unavailable(now)
        }
        val shell = try {
            shellProvider()
        } catch (_: Throwable) {
            null
        } ?: return unavailable(now)

        val config = FimConfig.DEFAULT
        val deadline = System.nanoTime() + COLLECT_BUDGET_NANOS
        val scanned = ArrayList<FimScannedFile>(256)
        val seenPaths = HashSet<String>(256)
        var truncated = false
        var rootFailures = 0
        var stop = false

        for (root in config.roots) {
            if (stop) break
            if (scanned.size >= config.maxTotalFiles) {
                truncated = true
                break
            }
            if (System.nanoTime() - deadline > 0L) {
                truncated = true
                break
            }
            val listing = listRoot(shell, root, config)
            if (listing == null) {
                rootFailures += 1
                continue
            }
            if (!listing.complete) truncated = true
            for (path in listing.files) {
                if (scanned.size >= config.maxTotalFiles) {
                    truncated = true
                    stop = true
                    break
                }
                if (System.nanoTime() - deadline > 0L) {
                    truncated = true
                    stop = true
                    break
                }
                if (!seenPaths.add(path)) continue
                val outcome = scanFile(shell, path, root.path, config.maxHashBytes) ?: continue
                if (outcome.hashSkipped) truncated = true
                scanned += outcome.file
            }
        }

        if (scanned.isEmpty()) return unavailable(now)
        val baseline = try {
            store.loadFimBaseline()
        } catch (_: Throwable) {
            null
        }
        val comparison = try {
            engine.compare(baseline, scanned, now)
        } catch (_: Throwable) {
            null
        } ?: return unavailable(now)
        if (comparison.baselineChanged) {
            val newBaseline = comparison.newBaseline
            if (newBaseline != null) {
                try {
                    store.saveFimBaseline(newBaseline)
                } catch (_: Throwable) {
                    // A failed baseline write only repeats the delta on the next pass.
                }
            }
        }
        var snapshot = comparison.snapshot
        if (truncated || rootFailures > 0) {
            // A coverage gap is more important than the engine's baseline note: the UI must never see a
            // truncated FIM pass without the explicit unreadable/limited signal.
            snapshot = snapshot.copy(
                truncated = true,
                visibility = if (snapshot.visibility == DataVisibility.FULL) DataVisibility.PARTIAL else snapshot.visibility,
                note = MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE),
            )
        }
        return snapshot
    }

    // -------------------------------------------------------------------- root listing

    private data class RootListing(val files: List<String>, val complete: Boolean)

    /**
     * Lists one watch root through the allow-listed `find` command.
     *
     * Returns `null` only when the channel failed (unavailable/timeout). A configured root that does
     * not exist on this build ("No such file or directory") yields a complete empty listing - normal
     * for e.g. `/system/xbin`.
     *
     * Every other outcome that reduces trustworthy coverage makes the listing incomplete: a non-zero
     * exit, a possibly truncated execute payload and - critically - any output line that is not a
     * valid, unique file path below the root. Such a line is either hostile input or an
     * unrepresentable file name (space/glob character/newline); silently dropping it would let an
     * attacker plant a file in a watched root while the scan claims a complete tree. The caller turns
     * an incomplete listing into `truncated` + PARTIAL visibility with a catalog note.
     */
    private fun listRoot(shell: TitanShell, root: FimWatchRoot, config: FimConfig): RootListing? {
        val command = try {
            TitanCommandFactory.listWatchRoot(root.path, root.recursive, root.maxDepth)
        } catch (_: Throwable) {
            return null
        }
        val result = try {
            shell.execute(command)
        } catch (_: Throwable) {
            return null
        }
        if (result.timedOut) return null
        val output = result.output
        if (!result.ok && isAbsentRootOutput(output)) return RootListing(emptyList(), complete = true)
        val parsed = TitanFindLineParser.parse(output, root.path, config.maxFilesPerRoot)
        val failureGap = !result.ok
        // TitanShellResult carries no truncation flag; a capped execute payload is detected by its size.
        val payloadSuspicious = output.length >= SUSPECT_OUTPUT_CHARS
        return RootListing(
            files = parsed.files,
            complete = !parsed.capped && !payloadSuspicious && parsed.rejectedLines == 0 && !failureGap,
        )
    }

    /** Only a missing path is "root absent"; every other `find` failure is a coverage gap. */
    private fun isAbsentRootOutput(output: String): Boolean = output.lowercase().contains("no such file")

    // --------------------------------------------------------------------- file scanning

    private data class ScanOutcome(val file: FimScannedFile, val hashSkipped: Boolean)

    private data class StatFacts(val permissions: String?, val sizeBytes: Long, val modifiedAtMillis: Long)

    /**
     * Reads metadata and (within the size cap) the SHA-256 of one watched file.
     *
     * Returns `null` only when the model rejects the path (hostile shell output); an unreadable or
     * over-cap file is reported as an explicit unreadable [FimScannedFile].
     */
    private fun scanFile(shell: TitanShell, path: String, watchedRoot: String, maxHashBytes: Long): ScanOutcome? {
        val statFacts = statFile(shell, path) ?: return unreadable(path, watchedRoot)
        if (statFacts.sizeBytes > maxHashBytes) {
            // Too large to hash within the policy cap: honest unreadable, and the pass is truncated.
            return unreadable(path, watchedRoot, statFacts)
        }
        val hash = sha256File(shell, path)
        val readable = hash != null
        return try {
            ScanOutcome(
                file = FimScannedFile(
                    path = path,
                    sha256 = hash,
                    sizeBytes = statFacts.sizeBytes,
                    modifiedAtMillis = statFacts.modifiedAtMillis,
                    permissions = statFacts.permissions,
                    watchedRoot = watchedRoot,
                    readable = readable,
                ),
                hashSkipped = false,
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun unreadable(path: String, watchedRoot: String): ScanOutcome? = unreadable(
        path = path,
        watchedRoot = watchedRoot,
        statFacts = StatFacts(permissions = null, sizeBytes = 0L, modifiedAtMillis = 0L),
    )

    private fun unreadable(path: String, watchedRoot: String, statFacts: StatFacts): ScanOutcome? {
        val permissions = statFacts.permissions?.takeIf { PERMISSION_PATTERN.matches(it) }
        return try {
            ScanOutcome(
                file = FimScannedFile(
                    path = path,
                    sha256 = null,
                    sizeBytes = statFacts.sizeBytes.coerceAtLeast(0L),
                    modifiedAtMillis = statFacts.modifiedAtMillis.coerceAtLeast(0L),
                    permissions = permissions,
                    watchedRoot = watchedRoot,
                    readable = false,
                ),
                hashSkipped = statFacts.sizeBytes > 0L,
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    private fun statFile(shell: TitanShell, path: String): StatFacts? {
        val command = try {
            TitanCommandFactory.statFile(path)
        } catch (_: Throwable) {
            return null
        }
        val output = executeReadOnly(shell, command) ?: return null
        return parseStat(output)
    }

    private fun sha256File(shell: TitanShell, path: String): String? {
        val command = try {
            TitanCommandFactory.sha256File(path)
        } catch (_: Throwable) {
            return null
        }
        val output = executeReadOnly(shell, command) ?: return null
        return parseSha256(output)
    }

    /** Executes one read-only command; `null` for any failure (unavailable, timeout, non-zero exit). */
    private fun executeReadOnly(shell: TitanShell, command: TitanShellCommand): String? {
        val result = try {
            shell.execute(command)
        } catch (_: Throwable) {
            return null
        }
        if (!result.ok || result.timedOut) return null
        return result.output
    }

    private fun parseStat(output: String): StatFacts? {
        if (output.isEmpty()) return null
        val line = output.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: return null
        val parts = line.split(':')
        if (parts.size != 3) return null
        if (!PERMISSION_PATTERN.matches(parts[0])) return null
        val size = parts[1].toLongOrNull()?.takeIf { it in 0L..MAX_SIZE_BYTES } ?: return null
        val seconds = parts[2].toLongOrNull()?.takeIf { it in 0L..MAX_EPOCH_SECONDS } ?: return null
        return StatFacts(
            permissions = parts[0],
            sizeBytes = size,
            modifiedAtMillis = seconds * 1_000L,
        )
    }

    private fun parseSha256(output: String): String? {
        if (output.isEmpty()) return null
        val line = output.lineSequence().firstOrNull { it.isNotBlank() }?.trim() ?: return null
        val token = line.substringBefore(' ').substringBefore('\t').lowercase()
        return token.takeIf { SHA256_PATTERN.matches(it) }
    }

    private fun unavailable(now: Long): FimSnapshot =
        FimSnapshot.empty(now, DataVisibility.PARTIAL, MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE))

    private companion object {
        const val COLLECT_BUDGET_NANOS = 180_000_000_000L
        const val SUSPECT_OUTPUT_CHARS = 60_000

        /** 1 PiB - far above any real file size but safe for millisecond arithmetic. */
        const val MAX_SIZE_BYTES = 1_125_899_906_842_624L
        const val MAX_EPOCH_SECONDS = 253_402_300_799L

        val SHA256_PATTERN = Regex("[0-9a-f]{64}")
        val PERMISSION_PATTERN = Regex("[0-7]{3,4}")
    }
}
