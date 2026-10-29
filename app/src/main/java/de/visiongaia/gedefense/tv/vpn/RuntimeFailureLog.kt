package de.visiongaia.gedefense.tv.vpn

import android.util.Log
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

/**
 * Bounded, privacy-safe reporting for explicitly non-critical best-effort failures.
 *
 * Ported from the mobile dossier: only a compile-time scope label and the exception class are recorded.
 * Exception messages, paths, package names, IPs and domains are never emitted. Repeated failures are
 * rate-limited to powers of two so a broken cleanup callback cannot flood logcat.
 */
internal object RuntimeFailureLog {
    private const val TAG = "GeDefenseFailure"
    private const val MAX_SCOPES = 64
    private const val MAX_SCOPE_LENGTH = 48
    private const val MAX_TYPE_LENGTH = 48
    private val counts = ConcurrentHashMap<String, AtomicLong>()

    fun nonCritical(scope: String, error: Throwable) {
        val safeScope = sanitizeScope(scope)
        var counter = counts[safeScope]
        if (counter == null) {
            if (counts.size >= MAX_SCOPES) {
                Log.w(TAG, "noncritical_failure:scope_capacity:${error.javaClass.simpleName.take(MAX_TYPE_LENGTH)}")
                return
            }
            counter = counts.computeIfAbsent(safeScope) { AtomicLong(0L) }
        }
        val count = counter.incrementAndGet()
        if (count == 1L || count and (count - 1L) == 0L) {
            Log.w(
                TAG,
                "noncritical_failure:$safeScope:${error.javaClass.simpleName.take(MAX_TYPE_LENGTH)}:count=$count",
            )
        }
    }

    private fun sanitizeScope(scope: String): String = scope.asSequence()
        .map { character ->
            when {
                character.isLetterOrDigit() -> character.lowercaseChar()
                character == '-' || character == '_' || character == '.' -> character
                else -> '_'
            }
        }
        .joinToString("")
        .take(MAX_SCOPE_LENGTH)
        .ifBlank { "unspecified" }
}
