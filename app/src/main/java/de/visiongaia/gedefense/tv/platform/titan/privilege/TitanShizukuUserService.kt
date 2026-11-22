package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.Context
import android.os.Binder
import android.os.Bundle
import android.os.Process as OsProcess
import de.visiongaia.gedefense.tv.BuildConfig
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-isolated Shizuku UserService running inside Shizuku's privileged `app_process`
 * (`uid=2000` shell or `uid=0` root).
 *
 * Security invariants (VGT-002 / VGT-010 / VGT-012):
 *  - No generic shell execution: no `sh`, no `su`, no metacharacters. Only an explicit minimal
 *    sub-allowlist of [TitanCommandFactory] programs valid at Level 2 may run directly via
 *    `ProcessBuilder(argv)`.
 *  - Caller UID verification: refuses Binder callers whose UID does not match either this
 *    service's own UID or the owning GeDefense TV package UID when [Context] is available.
 *  - Hard wall-clock timeout and stream output cap prevent pipe blocking and memory amplification.
 */
class TitanShizukuUserService : ITitanShizukuBridge.Stub {

    private val appContext: Context?

    @Volatile
    private var cachedOwnerUid: Int? = null

    constructor() {
        this.appContext = null
    }

    constructor(context: Context) {
        this.appContext = context.applicationContext ?: context
    }

    override fun probeIdentity(): String {
        verifyCaller()
        val result = runProcess("id", emptyList(), DEFAULT_PROBE_TIMEOUT_MS, SMALL_OUTPUT_CAP)
        return if (result.getBoolean(KEY_OK)) result.getString(KEY_OUTPUT, "").take(256) else ""
    }

    override fun runAllowlisted(
        program: String?,
        args: Array<out String>?,
        timeoutMillis: Long,
        maxBytes: Int,
    ): Bundle {
        verifyCaller()
        val safeProgram = program?.trim().orEmpty()
        val safeArgs = args?.toList().orEmpty()
        if (safeProgram !in ALLOWED_SHIZUKU_PROGRAMS || safeArgs.size > MAX_ARGS || !safeArgs.all {
                it.length in 1..MAX_ARG_CHARS && SAFE_ARG_PATTERN.matches(it)
            }
        ) {
            return failureBundle()
        }
        return runProcess(safeProgram, safeArgs, timeoutMillis, maxBytes)
    }

    override fun destroy() {
        verifyCaller()
        System.exit(0)
    }

    private fun verifyCaller() {
        val callingUid = Binder.getCallingUid()
        if (callingUid == OsProcess.myUid()) return
        val ctx = appContext ?: return
        val expectedUid = resolveOwnerUid(ctx) ?: throw SecurityException("owner uid unresolved")
        if (callingUid != expectedUid) {
            throw SecurityException("unauthorized caller uid=$callingUid")
        }
    }

    private fun resolveOwnerUid(context: Context): Int? {
        cachedOwnerUid?.let { return it }
        return try {
            val uid = context.packageManager.getPackageUid(BuildConfig.APPLICATION_ID, 0)
            cachedOwnerUid = uid
            uid
        } catch (_: Throwable) {
            null
        }
    }

    private fun runProcess(
        program: String,
        args: List<String>,
        timeoutMillis: Long,
        maxBytes: Int,
    ): Bundle {
        val cap = maxBytes.coerceIn(MIN_OUTPUT_BYTES, MAX_OUTPUT_BYTES)
        val timeout = timeoutMillis.coerceIn(MIN_TIMEOUT_MS, MAX_TIMEOUT_MS)
        val argv = ArrayList<String>(1 + args.size).apply {
            add(program)
            addAll(args)
        }
        val process = try {
            ProcessBuilder(argv).redirectErrorStream(true).start()
        } catch (_: Throwable) {
            return failureBundle()
        }
        val captured = ByteArrayOutputStream(4096)
        val truncated = AtomicBoolean(false)
        val drainThread = Thread(
            { drain(process.inputStream, cap, captured, truncated) },
            "gedefense-shizuku-drain",
        ).apply {
            isDaemon = true
            start()
        }
        val finished = try {
            process.waitFor(timeout, TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Throwable) {
            false
        }
        if (!finished) {
            destroyQuietly(process)
            closeQuietly(process.inputStream)
            joinQuietly(drainThread, CLEANUP_JOIN_MS)
            return Bundle().apply {
                putBoolean(KEY_STARTED, true)
                putBoolean(KEY_OK, false)
                putInt(KEY_EXIT_CODE, -2)
                putBoolean(KEY_TIMED_OUT, true)
                putBoolean(KEY_TRUNCATED, truncated.get())
                putString(KEY_OUTPUT, snapshot(captured))
            }
        }
        joinQuietly(drainThread, DRAIN_JOIN_MS)
        if (drainThread.isAlive) closeQuietly(process.inputStream)
        joinQuietly(drainThread, CLEANUP_JOIN_MS)
        val exitCode = try {
            process.exitValue()
        } catch (_: Throwable) {
            -1
        }
        return Bundle().apply {
            putBoolean(KEY_STARTED, true)
            putBoolean(KEY_OK, exitCode == 0)
            putInt(KEY_EXIT_CODE, exitCode)
            putBoolean(KEY_TIMED_OUT, false)
            putBoolean(KEY_TRUNCATED, truncated.get())
            putString(KEY_OUTPUT, snapshot(captured))
        }
    }

    private fun drain(
        input: InputStream,
        cap: Int,
        sink: ByteArrayOutputStream,
        truncated: AtomicBoolean,
    ) {
        val buffer = ByteArray(4096)
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
            // Stream closed after process exit/destroy.
        } catch (_: RuntimeException) {
            // Bounded drain stays fault-isolated.
        }
    }

    private fun snapshot(sink: ByteArrayOutputStream): String = synchronized(sink) {
        String(sink.toByteArray(), Charsets.UTF_8)
    }

    private fun failureBundle(): Bundle = Bundle().apply {
        putBoolean(KEY_STARTED, false)
        putBoolean(KEY_OK, false)
        putInt(KEY_EXIT_CODE, -1)
        putBoolean(KEY_TIMED_OUT, false)
        putBoolean(KEY_TRUNCATED, false)
        putString(KEY_OUTPUT, "")
    }

    private fun destroyQuietly(process: Process) {
        try {
            process.destroyForcibly()
        } catch (_: Throwable) {
            // Already dead.
        }
    }

    private fun closeQuietly(input: InputStream) {
        try {
            input.close()
        } catch (_: Throwable) {
            // Already closed.
        }
    }

    private fun joinQuietly(thread: Thread, millis: Long) {
        try {
            thread.join(millis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    companion object {
        const val KEY_STARTED = "started"
        const val KEY_OK = "ok"
        const val KEY_EXIT_CODE = "exitCode"
        const val KEY_TIMED_OUT = "timedOut"
        const val KEY_TRUNCATED = "truncated"
        const val KEY_OUTPUT = "output"

        val ALLOWED_SHIZUKU_PROGRAMS: Set<String> = setOf(
            "pm",
            "am",
            "cmd",
            "getprop",
            "id",
            "cat",
            "ls",
        )
        private val SAFE_ARG_PATTERN = Regex("[A-Za-z0-9_./:@+=,%-]+")
        private const val MAX_ARGS = 16
        private const val MAX_ARG_CHARS = 512
        private const val MIN_OUTPUT_BYTES = 512
        private const val MAX_OUTPUT_BYTES = 512 * 1024
        private const val SMALL_OUTPUT_CAP = 2 * 1024
        private const val MIN_TIMEOUT_MS = 250L
        private const val MAX_TIMEOUT_MS = 30_000L
        private const val DEFAULT_PROBE_TIMEOUT_MS = 3_000L
        private const val DRAIN_JOIN_MS = 2_000L
        private const val CLEANUP_JOIN_MS = 200L
    }
}
