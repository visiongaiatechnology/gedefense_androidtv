package de.visiongaia.gedefense.tv.data

import android.os.Looper
import java.security.GeneralSecurityException
import java.util.concurrent.Callable
import java.util.concurrent.ExecutionException
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.SynchronousQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.ReentrantLock

/**
 * Process-wide fail-closed isolation boundary for AndroidKeyStore provider/Binder operations.
 *
 * Ported from the GeDefense mobile dossier (same semantics): OEM providers may block in
 * native/Binder code instead of throwing, so calls execute on a single daemon worker with an
 * operation deadline. A fair admission lock prevents unbounded queues and keeps queue wait separate
 * from provider execution time. After the first provider execution timeout the process circuit opens
 * permanently and every later operation fails immediately. Main-thread Keystore access is rejected
 * instead of risking an ANR on the TV.
 */
object AndroidKeystoreGate {
    class UnavailableException internal constructor(
        val reasonCode: String,
        cause: Throwable? = null,
    ) : GeneralSecurityException(reasonCode, cause)

    private const val OPERATION_TIMEOUT_MILLIS = 5_000L
    private const val ADMISSION_TIMEOUT_MILLIS = 10_000L
    private val circuitOpen = AtomicBoolean(false)
    private val admission = ReentrantLock(true)
    private val executor = ThreadPoolExecutor(
        1,
        1,
        0L,
        TimeUnit.MILLISECONDS,
        SynchronousQueue(),
        { runnable -> Thread(runnable, "gedefense-tv-keystore-gate").apply { isDaemon = true } },
        ThreadPoolExecutor.AbortPolicy(),
    )

    fun isAvailable(): Boolean = !circuitOpen.get()

    fun isMainThread(): Boolean = Looper.myLooper() == Looper.getMainLooper()

    @Throws(Exception::class)
    fun <T> call(action: () -> T): T {
        if (isMainThread()) throw UnavailableException("keystore_main_thread_forbidden")
        if (circuitOpen.get()) throw UnavailableException("keystore_circuit_open")

        val admitted = try {
            admission.tryLock(ADMISSION_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
        } catch (error: InterruptedException) {
            Thread.currentThread().interrupt()
            throw UnavailableException("keystore_admission_interrupted", error)
        }
        if (!admitted) throw UnavailableException("keystore_admission_timeout")

        try {
            if (circuitOpen.get()) throw UnavailableException("keystore_circuit_open")
            val future = try {
                executor.submit(Callable { action() })
            } catch (error: RejectedExecutionException) {
                throw UnavailableException("keystore_executor_unavailable", error)
            }
            return try {
                future.get(OPERATION_TIMEOUT_MILLIS, TimeUnit.MILLISECONDS)
            } catch (error: TimeoutException) {
                if (circuitOpen.compareAndSet(false, true)) executor.shutdownNow()
                future.cancel(true)
                throw UnavailableException("keystore_operation_timeout", error)
            } catch (error: InterruptedException) {
                future.cancel(true)
                Thread.currentThread().interrupt()
                throw UnavailableException("keystore_operation_interrupted", error)
            } catch (error: ExecutionException) {
                val cause = error.cause
                when (cause) {
                    is RuntimeException -> throw cause
                    is Error -> throw cause
                    is Exception -> throw cause
                    else -> throw UnavailableException("keystore_operation_failed", error)
                }
            }
        } finally {
            admission.unlock()
        }
    }
}
