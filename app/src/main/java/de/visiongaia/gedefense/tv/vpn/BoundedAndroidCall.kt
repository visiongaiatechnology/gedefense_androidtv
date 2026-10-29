package de.visiongaia.gedefense.tv.vpn

import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * Bounds Android framework/Binder calls that are outside GeDefense's cancellation control.
 *
 * Ported from the mobile dossier: a timed-out Binder call may keep one daemon worker occupied, but the
 * fixed pool with a zero-capacity queue caps the blast radius. Callers must degrade explicitly on
 * timeout/rejection; this gate never converts an unavailable platform service into a successful result.
 */
object BoundedAndroidCall {
    private const val WORKERS = 4
    const val DEFAULT_TIMEOUT_MS = 3_000L

    private val executor = ThreadPoolExecutor(
        WORKERS,
        WORKERS,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable -> Thread(runnable, "gedefense-tv-platform-call").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun <T> call(timeoutMillis: Long = DEFAULT_TIMEOUT_MS, action: () -> T): T {
        require(timeoutMillis in 1L..30_000L) { "platform call timeout outside allowed range" }
        val future = try {
            executor.submit<T> { action() }
        } catch (error: RejectedExecutionException) {
            throw PlatformCallUnavailableException("platform_call_capacity_exhausted", error)
        }
        return try {
            future.get(timeoutMillis, TimeUnit.MILLISECONDS)
        } catch (error: TimeoutException) {
            future.cancel(true)
            throw PlatformCallUnavailableException("platform_call_timeout", error)
        } catch (error: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw PlatformCallUnavailableException("platform_call_interrupted", error)
        } catch (error: java.util.concurrent.ExecutionException) {
            val cause = error.cause ?: error
            if (cause is RuntimeException) throw cause
            throw PlatformCallUnavailableException("platform_call_failed", cause)
        }
    }
}

class PlatformCallUnavailableException(
    val reasonCode: String,
    cause: Throwable? = null,
) : RuntimeException(reasonCode, cause)
