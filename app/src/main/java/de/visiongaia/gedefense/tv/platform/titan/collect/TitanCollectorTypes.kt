package de.visiongaia.gedefense.tv.platform.titan.collect

import de.visiongaia.gedefense.tv.core.titan.model.TitanFimPolicy

/**
 * Pure parser for the `find -print` output of the FIM collector.
 *
 * The watch-root command is allow-listed by [de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory]
 * and therefore emits newline-separated paths (`-print`). That encoding cannot represent every
 * possible filename faithfully: a file name with a newline splits into several output lines, and the
 * FIM path policy rejects names with spaces or shell/glob characters (`?`, `*`, `!`, `(`, `)`, `[`,
 * `]`, `{`, `}`, ...). Dropping such lines silently would let an attacker plant an unreadable file in
 * a watched root while the scan still claims a complete, unchanged tree (exactly the FIM threat
 * model, where an attacker already has shell access).
 *
 * Therefore this parser never silently drops a line: every line that is not a valid, unique file path
 * below the root is counted in [Parsed.rejectedLines]. The collector turns any rejected line into a
 * coverage gap (incomplete listing -> `truncated` + PARTIAL visibility + `TitanTextKeys.NOTE_FIM_UNREADABLE`).
 *
 * The parser is pure and bounded: it never throws, never follows paths and is only as expensive as the
 * already output-capped shell payload it receives.
 */
internal object TitanFindLineParser {
    const val MAX_PATH_LENGTH = 512

    /** Result of one `find -print` parse. [rejectedLines] > 0 always means a coverage gap. */
    data class Parsed(
        val files: List<String>,
        val rejectedLines: Int,
        val capped: Boolean,
    )

    /**
     * Parses [output] for one watch root.
     *
     * @param output raw merged stdout/stderr of the read-only `find` command.
     * @param rootPath configured watch root (already validated by the caller).
     * @param limit per-root file cap; when the cap is reached [Parsed.capped] is true.
     */
    fun parse(output: String, rootPath: String, limit: Int): Parsed {
        if (limit <= 0 || output.isEmpty()) return Parsed(emptyList(), 0, capped = false)
        val rootPrefix = rootPath + "/"
        val lines = output.lineSequence().toList()
        val files = ArrayList<String>(minOf(limit, 128))
        val seen = HashSet<String>(minOf(limit * 2, 1_024))
        var rejected = 0
        var capped = false
        for ((index, line) in lines.withIndex()) {
            if (files.size >= limit) {
                capped = true
                break
            }
            // A single final empty line is the normal `-print` terminator; every other blank line can
            // only be the artefact of a file name that contains a line break.
            if (line.isEmpty()) {
                if (index == lines.lastIndex && lines.size > 1) continue
                rejected += 1
                continue
            }
            if (line.length > MAX_PATH_LENGTH) {
                rejected += 1
                continue
            }
            if (!line.startsWith(rootPrefix)) {
                // Diagnostics, foreign paths or split hostile names: none is a trustworthy file row.
                rejected += 1
                continue
            }
            if (!TitanFimPolicy.isSafeAbsolutePath(line)) {
                // Watched but unrepresentable name (space, glob/shell metacharacter, '..', control).
                rejected += 1
                continue
            }
            if (!seen.add(line)) continue
            files += line
        }
        return Parsed(files = files, rejectedLines = rejected, capped = capped)
    }
}
