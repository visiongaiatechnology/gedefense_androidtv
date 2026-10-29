package de.visiongaia.gedefense.mobile.core

import java.security.GeneralSecurityException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.locks.ReentrantLock
import javax.crypto.SecretKey

// STATUS: PLATIN
/**
 * Isolates operations backed by opaque/non-exportable SecretKeys.
 *
 * Opaque providers may block in native/Binder code instead of throwing. A fair admission lock
 * serializes such operations without an unbounded executor queue. Provider execution receives its
 * own deadline after admission, so legitimate queue wait never masquerades as a provider hang.
 * The first execution timeout opens a permanent process circuit and abandons at most one daemon
 * worker. Exportable software keys execute directly on the caller thread.
 */
object BoundedSecretKeyCrypto {
    private const val DEFAULT_TIMEOUT_MILLIS = 5_000L
    private const val ADMISSION_TIMEOUT_MILLIS = 10_000L
    private val circuitOpen = AtomicBoolean(false)
    private val admission = ReentrantLock(true)
    private val threadIds = AtomicInteger(0)
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable ->
            Thread(runnable, "gedefense-opaque-crypto-${threadIds.incrementAndGet()}").apply { isDaemon = true }
        },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun isOpaque(key: SecretKey): Boolean = try {
        key.format == null
    } catch (_: RuntimeException) {
        true
    }

    @Throws(GeneralSecurityException::class)
    fun <T> execute(
        key: SecretKey,
        timeoutMillis: Long = DEFAULT_TIMEOUT_MILLIS,
        operation: () -> T,
    ): T {
        require(timeoutMillis in 1L..30_000L) { "opaque crypto timeout out of bounds" }
        if (!isOpaque(key)) return operation()
        if (circuitOpen.get()) throw GeneralSecurityException("opaque key provider unavailable")

        val admitted = try {
            admission.tryLock(ADMISSION_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw GeneralSecurityException("opaque key admission interrupted", error)
        }
        if (!admitted) throw GeneralSecurityException("opaque key provider busy")

        try {
            if (circuitOpen.get()) throw GeneralSecurityException("opaque key provider unavailable")
            val future = try {
                executor.submit(Callable { operation() })
            } catch (error: RejectedExecutionException) {
                throw GeneralSecurityException("opaque key provider unavailable", error)
            }
            return try {
                future.get(timeoutMillis, TimeUnit.MILLISECONDS)
            } catch (error: TimeoutException) {
                if (circuitOpen.compareAndSet(false, true)) executor.shutdownNow()
                future.cancel(true)
                throw GeneralSecurityException("opaque key provider timeout", error)
            } catch (error: InterruptedException) {
                future.cancel(true)
                Thread.currentThread().interrupt()
                throw GeneralSecurityException("opaque key operation interrupted", error)
            } catch (error: ExecutionException) {
                val cause = error.cause
                when (cause) {
                    is GeneralSecurityException -> throw cause
                    is RuntimeException -> throw cause
                    is Error -> throw cause
                    is Exception -> throw GeneralSecurityException("opaque key operation failed", cause)
                    else -> throw GeneralSecurityException("opaque key operation failed", error)
                }
            }
        } finally {
            admission.unlock()
        }
    }
}
