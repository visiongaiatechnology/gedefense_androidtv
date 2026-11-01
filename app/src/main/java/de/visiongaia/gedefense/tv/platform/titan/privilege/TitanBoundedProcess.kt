package de.visiongaia.gedefense.tv.platform.titan.privilege

import de.visiongaia.gedefense.tv.core.titan.response.TitanShellCommand
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The single process-execution chokepoint of the Titan platform layer.
 *
 * There is deliberately no generic `exec(program, args)` API: the module-internal allowlist below
 * accepts exactly three invocation shapes and rejects everything else before a `ProcessBuilder` is
 * created.
 *
 *  - `su -c <shell line>`: the line must match the same conservative charset as
 *    [TitanShellCommand] arguments and start with a [TitanShellCommand.ALLOWED_PROGRAMS] program.
 *    This is defence in depth on top of the validated command object; a caller can never smuggle an
 *    arbitrary string through this layer.
 *  - `getenforce`: passive SELinux state, no arguments.
 *  - `getprop <property>`: passive build properties, property name restricted to the Android
 *    property charset.
 *
 * Every invocation is bounded: a fixed wall-clock timeout, a hard output cap (bytes beyond the cap
 * are drained and discarded so the child can never block on a full pipe), one daemon drain thread,
 * and a forced destroy on timeout. The helper never throws; degraded situations are reported as
 * [Outcome.NOT_STARTED] or `timedOut = true`.
 */
internal object TitanBoundedProcess {

    /** Bounded outcome of one local process invocation. Never contains a command line or secrets. */
    data class Outcome(
        val started: Boolean,
        val exitCode: Int,
        val timedOut: Boolean,
        val truncated: Boolean,
        val output: String,
    ) {
        companion object {
            val NOT_STARTED = Outcome(
                started = false,
                exitCode = -1,
                timedOut = false,
                truncated = false,
                output = "",
            )
        }
    }

    private const val MIN_TIMEOUT_MILLIS = 250L
    private const val MAX_TIMEOUT_MILLIS = 30_000L
    private const val MIN_OUTPUT_BYTES = 512
    private const val MAX_OUTPUT_BYTES = 512 * 1024
    private const val INITIAL_BUFFER_BYTES = 8 * 1024
    private const val DRAIN_BUFFER_BYTES = 4 * 1024
    private const val DRAIN_JOIN_MILLIS = 2_000L
    private const val CLEANUP_JOIN_MILLIS = 200L
    private const val MAX_ARGV = 4
    private const val MAX_SU_COMMAND_CHARS = 8_192
    private const val SU_PROGRAM = "su"
    private const val GETENFORCE_PROGRAM = "getenforce"
    private const val GETPROP_PROGRAM = "getprop"
    private val PROPERTY_PATTERN = Regex("[a-z][a-z0-9._-]{0,63}")

    /**
     * Defence-in-depth re-check of the joined `su -c` line: one program token plus space-separated
     * argument tokens from a conservative charset. `%` is included because the domain `stat`
     * verification uses a POSIX format string; every token is still shell-metacharacter free.
     * Keep in sync with `TitanShellCommand.SAFE_ARGUMENT` in `:tv-core`.
     */
    private val SHELL_LINE_PATTERN = Regex("[A-Za-z0-9_./:@+=,%-]+(?: [A-Za-z0-9_./:@+=,%-]+)*")

    /**
     * Runs one allow-listed invocation.
     *
     * @param argv fixed invocation (program plus at most two arguments).
     * @param workingDirectory optional app-owned working directory; null keeps the process default.
     * @param timeoutMillis clamped to 250..30 000 ms.
     * @param maxBytes output cap clamped to 512 B..512 KiB.
     */
    fun run(
        argv: List<String>,
        workingDirectory: File?,
        timeoutMillis: Long,
        maxBytes: Int,
    ): Outcome {
        if (argv.isEmpty() || argv.size > MAX_ARGV || !isAllowedInvocation(argv)) return Outcome.NOT_STARTED
        val cap = maxBytes.coerceIn(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)
        val process = try {
            val builder = ProcessBuilder(argv).redirectErrorStream(true)
            if (workingDirectory != null) builder.directory(workingDirectory)
            builder.start()
        } catch (_: IOException) {
            return Outcome.NOT_STARTED
        } catch (_: SecurityException) {
            return Outcome.NOT_STARTED
        } catch (_: RuntimeException) {
            return Outcome.NOT_STARTED
        }
        val captured = ByteArrayOutputStream(INITIAL_BUFFER_BYTES)
        val truncated = AtomicBoolean(false)
        val reader = Thread(
            { drain(process.inputStream, cap, captured, truncated) },
            "gedefense-tv-titan-process-drain",
        ).apply {
            isDaemon = true
            start()
        }
        val finished = try {
            process.waitFor(timeoutMillis.coerceIn(MIN_TIMEOUT_MILLIS, MAX_TIMEOUT_MILLIS), TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: RuntimeException) {
            false
        }
        if (!finished) {
            // Forced destroy plus stream close: the drain thread is bounded even if a grandchild
            // process still holds the pipe open.
            destroyQuietly(process)
            joinQuietly(reader, CLEANUP_JOIN_MILLIS)
            closeQuietly(process.inputStream)
            joinQuietly(reader, CLEANUP_JOIN_MILLIS)
            return Outcome(
                started = true,
                exitCode = -1,
                timedOut = true,
                truncated = truncated.get(),
                output = snapshot(captured),
            )
        }
        joinQuietly(reader, DRAIN_JOIN_MILLIS)
        if (reader.isAlive) closeQuietly(process.inputStream)
        joinQuietly(reader, CLEANUP_JOIN_MILLIS)
        val exitCode = try {
            process.exitValue()
        } catch (_: IllegalThreadStateException) {
            -1
        }
        return Outcome(
            started = true,
            exitCode = exitCode,
            timedOut = false,
            truncated = truncated.get(),
            output = snapshot(captured),
        )
    }

    private fun isAllowedInvocation(argv: List<String>): Boolean {
        val program = argv[0]
        return when {
            program == SU_PROGRAM || program in TitanShell.SU_CANDIDATES -> isAllowedSuInvocation(argv)
            program == GETENFORCE_PROGRAM -> argv.size == 1
            program == GETPROP_PROGRAM -> argv.size == 2 && PROPERTY_PATTERN.matches(argv[1])
            else -> false
        }
    }

    private fun isAllowedSuInvocation(argv: List<String>): Boolean {
        if (argv.size != 3 || argv[1] != "-c") return false
        val line = argv[2]
        if (line.length !in 1..MAX_SU_COMMAND_CHARS || !SHELL_LINE_PATTERN.matches(line)) return false
        return line.substringBefore(' ') in TitanShellCommand.ALLOWED_PROGRAMS
    }

    private fun drain(
        input: InputStream,
        cap: Int,
        sink: ByteArrayOutputStream,
        truncated: AtomicBoolean,
    ) {
        val buffer = ByteArray(DRAIN_BUFFER_BYTES)
        try {
            while (!Thread.currentThread().isInterrupted) {
                val read = input.read(buffer)
                if (read < 0) return
                if (read == 0) continue
                synchronized(sink) {
                    val remaining = cap - sink.size()
                    if (remaining > 0) sink.write(buffer, 0, minOf(remaining, read))
                    if (read > remaining) truncated.set(true)
                }
            }
        } catch (_: IOException) {
            // Stream closed after a timeout; the captured prefix is reported as truncated/partial.
        } catch (_: RuntimeException) {
            // Same contract as IOException: never let a drain failure escape the worker thread.
        }
    }

    private fun snapshot(stream: ByteArrayOutputStream): String = synchronized(stream) {
        String(stream.toByteArray(), Charsets.UTF_8)
    }

    private fun destroyQuietly(process: Process) {
        try {
            process.destroyForcibly()
        } catch (_: RuntimeException) {
            // The process is already gone or cannot be destroyed; the outcome is still bounded.
        }
    }

    private fun closeQuietly(input: InputStream) {
        try {
            input.close()
        } catch (_: IOException) {
            // Already closed by the process exit; nothing to recover.
        }
    }

    private fun joinQuietly(thread: Thread, millis: Long) {
        try {
            thread.join(millis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }
}
