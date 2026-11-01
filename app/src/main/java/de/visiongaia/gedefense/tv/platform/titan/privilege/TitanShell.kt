package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.Context
import android.util.Log
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory
import de.visiongaia.gedefense.tv.core.titan.response.TitanShellCommand
import java.io.File

/**
 * Bounded result of one command executed through the confirmed root shell channel.
 *
 * [ok] means "the command process started, ran to completion and exited with 0". It never implies
 * that the intended effect happened: effect verification is a separate step in
 * [TitanResponseEngine]. [output] is bounded by the executor and may be a prefix when
 * [timedOut] is true or when a table read hit its hard cap.
 */
data class TitanShellResult(
    val ok: Boolean,
    val exitCode: Int,
    val output: String,
    val timedOut: Boolean,
    val failure: TitanActionFailure? = null,
) {
    init {
        require(output.length <= MAX_OUTPUT_CHARS) { "titan shell output too large" }
        require(!ok || !timedOut) { "timed out command cannot be ok" }
        require(ok || failure != null) { "failed command requires a failure code" }
        require(failure == null || !ok) { "successful command must not carry a failure" }
    }

    /** One-line, secret-free summary for audit details. Never contains raw command output. */
    fun auditSummary(): String = "exit=$exitCode timedOut=$timedOut failure=${failure?.name?.lowercase() ?: "none"}"

    companion object {
        /** Sentinel used when `su` could not be started at all (binary absent or exec denied). */
        const val EXIT_NOT_STARTED = -1

        /** Sentinel used when the bounded wait expired and the process was forcibly destroyed. */
        const val EXIT_TIMEOUT = -2

        /** Upper bound of one result payload; equals the largest table-read cap in characters. */
        const val MAX_OUTPUT_CHARS = 512 * 1024
    }
}

/**
 * Executor of the user-confirmed root shell channel.
 *
 * Only [TitanShellCommand] instances can be executed; their arguments are charset-validated by the
 * domain layer and the executor re-checks the resulting line in [TitanBoundedProcess]. There is no
 * arbitrary `exec(String)` API on purpose.
 *
 * Security decisions:
 *  - `su` is resolved from the fixed candidate list instead of trusting the inherited `PATH`; only
 *    when no candidate exists does the plain `su` name fall back to `PATH` resolution.
 *  - Child processes inherit no user data, run with an app-owned working directory and get a hard
 *    wall-clock timeout plus a hard output cap.
 *  - Command arguments and raw output are never logged; only [TitanShellCommand.auditTag] appears
 *    in a log line.
 *  - Every failure is converted into a [TitanShellResult] with an explicit
 *    [TitanActionFailure]; no method throws for missing `su`, a hanging prompt or a killed process.
 *
 * Threading: the executor has no shared mutable state, so concurrent calls are safe. Each call owns
 * at most one daemon drain thread that is joined (or stream-closed) before returning.
 */
class TitanShell(context: Context) {

    private val workingDirectory: File =
        context.applicationContext.filesDir.takeIf { it.isDirectory } ?: File("/")

    private val suProgram: String = resolveSuProgram()

    /** Runs the explicit root-identity probe (`id`) through the shell channel. Default 5 s. */
    fun probeRoot(timeoutMillis: Long = DEFAULT_PROBE_TIMEOUT_MILLIS): TitanShellResult =
        run(TitanCommandFactory.probeRootIdentity(), timeoutMillis, EXECUTE_OUTPUT_CAP_BYTES)

    /** Executes one allow-listed command. Default 8 s. Never throws. */
    fun execute(command: TitanShellCommand, timeoutMillis: Long = DEFAULT_EXECUTE_TIMEOUT_MILLIS): TitanShellResult =
        run(command, timeoutMillis, EXECUTE_OUTPUT_CAP_BYTES)

    /** Executes a bounded batch sequentially; the list is capped at [MAX_BATCH_COMMANDS]. */
    fun executeAll(
        commands: List<TitanShellCommand>,
        timeoutMillis: Long = DEFAULT_EXECUTE_TIMEOUT_MILLIS,
    ): List<TitanShellResult> = commands.take(MAX_BATCH_COMMANDS).map { command -> execute(command, timeoutMillis) }

    /**
     * Reads one read-only table over the shell channel.
     *
     * Returns `null` when the channel is unavailable, the command timed out, exited non-zero or
     * produced more than [maxBytes]: a truncated table is treated as unreadable instead of being
     * silently parsed as complete data.
     */
    fun readTable(command: TitanShellCommand, maxBytes: Int = DEFAULT_TABLE_CAP_BYTES): String? {
        val outcome = TitanBoundedProcess.run(
            argv = shellCommandLine(command),
            workingDirectory = workingDirectory,
            timeoutMillis = DEFAULT_EXECUTE_TIMEOUT_MILLIS,
            maxBytes = maxBytes.coerceIn(MIN_TABLE_CAP_BYTES, MAX_TABLE_CAP_BYTES),
        )
        return when {
            !outcome.started -> null
            outcome.timedOut -> null
            outcome.exitCode != 0 -> null
            outcome.truncated -> null
            else -> outcome.output
        }
    }

    private fun run(command: TitanShellCommand, timeoutMillis: Long, maxBytes: Int): TitanShellResult {
        val outcome = TitanBoundedProcess.run(
            argv = shellCommandLine(command),
            workingDirectory = workingDirectory,
            timeoutMillis = timeoutMillis.coerceIn(MIN_TIMEOUT_MILLIS, MAX_TIMEOUT_MILLIS),
            maxBytes = maxBytes,
        )
        return when {
            !outcome.started -> {
                Log.w(TAG, "titan_shell_unavailable:${command.auditTag}")
                TitanShellResult(
                    ok = false,
                    exitCode = TitanShellResult.EXIT_NOT_STARTED,
                    output = "",
                    timedOut = false,
                    failure = TitanActionFailure.UNAVAILABLE,
                )
            }

            outcome.timedOut -> {
                Log.w(TAG, "titan_shell_timeout:${command.auditTag}")
                TitanShellResult(
                    ok = false,
                    exitCode = TitanShellResult.EXIT_TIMEOUT,
                    output = outcome.output,
                    timedOut = true,
                    failure = TitanActionFailure.COMMAND_FAILED,
                )
            }

            outcome.exitCode != 0 -> TitanShellResult(
                ok = false,
                exitCode = outcome.exitCode,
                output = outcome.output,
                timedOut = false,
                failure = TitanActionFailure.COMMAND_FAILED,
            )

            else -> TitanShellResult(
                ok = true,
                exitCode = 0,
                output = outcome.output,
                timedOut = false,
                failure = null,
            )
        }
    }

    private fun shellCommandLine(command: TitanShellCommand): List<String> =
        listOf(suProgram, "-c", command.shellLine())

    private fun resolveSuProgram(): String {
        for (candidate in SU_CANDIDATES) {
            val file = File(candidate)
            if (file.isFile && file.canExecute()) return candidate
        }
        return SU_PROGRAM
    }

    companion object {
        /**
         * Existing `su` binary candidates in the order the root managers install them. Used both for
         * passive detection ([TitanPrivilegeGate]) and for executor resolution, so detection and
         * execution can never disagree about where `su` lives.
         */
        val SU_CANDIDATES: List<String> = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/su/bin/su",
        )

        /** Explicit root confirmation probe; deliberately longer than a passive property read. */
        const val DEFAULT_PROBE_TIMEOUT_MILLIS = 5_000L

        /** Default timeout of a containment/verification command. */
        const val DEFAULT_EXECUTE_TIMEOUT_MILLIS = 8_000L

        const val MIN_TIMEOUT_MILLIS = 250L
        const val MAX_TIMEOUT_MILLIS = 30_000L

        /** Hard per-stream output cap of [execute] / [probeRoot] results. */
        const val EXECUTE_OUTPUT_CAP_BYTES = 64 * 1024

        /** Default and hard bounds of a [readTable] payload. */
        const val DEFAULT_TABLE_CAP_BYTES = 256 * 1024
        const val MIN_TABLE_CAP_BYTES = 4 * 1024
        const val MAX_TABLE_CAP_BYTES = 512 * 1024

        /** Upper bound of one [executeAll] batch; the response engine needs at most a few commands. */
        const val MAX_BATCH_COMMANDS = 16

        private const val TAG = "GeDefenseTv"
        private const val SU_PROGRAM = "su"
    }
}
