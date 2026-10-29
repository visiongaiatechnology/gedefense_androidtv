package de.visiongaia.gedefense.tv.platform

import android.app.job.JobParameters
import android.app.job.JobService
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.contract.ThreatIntelSyncListener
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ThreatIntelStatus
import de.visiongaia.gedefense.tv.data.TvThreatIntelRepository
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Periodic background job for the threat-intel feed sync (declared in the manifest).
 *
 * The job does not download anything itself: it delegates to [TvServices.threatIntel], which owns the
 * bounded download pipeline. The job service only bridges [JobScheduler] reschedule semantics, so a
 * failure requests a retry and a cancellation is reported honestly to the scheduler.
 *
 * If the service container is not available (for example a cold process whose application bootstrap
 * failed), the job finishes as failed and asks for a retry instead of crashing the process.
 */
class TvThreatIntelJobService : JobService() {
    private val lock = Any()
    private val token = AtomicLong(0L)
    private val active = AtomicBoolean(false)

    override fun onStartJob(params: JobParameters): Boolean {
        val services = try {
            TvServices.get(this)
        } catch (_: Throwable) {
            null
        }
        if (services == null) {
            jobFinished(params, true)
            return false
        }
        if (!active.compareAndSet(false, true)) return false
        val startToken = token.incrementAndGet()
        val started = try {
            services.threatIntel.syncNow(object : ThreatIntelSyncListener {
                override fun onSyncFinished(ok: Boolean, message: MessageRef, status: ThreatIntelStatus) {
                    complete(startToken, params, reschedule = !ok)
                }
            })
        } catch (_: Throwable) {
            false
        }
        if (!started) {
            // A sync is already running (manual or another job); let the scheduler retry later.
            complete(startToken, params, reschedule = true)
            return false
        }
        return true
    }

    override fun onStopJob(params: JobParameters): Boolean {
        token.incrementAndGet()
        active.set(false)
        // The repository has no cancellation contract; ask the scheduler to run the job again.
        return true
    }

    private fun complete(startToken: Long, params: JobParameters, reschedule: Boolean) {
        synchronized(lock) {
            if (token.get() != startToken) return
            active.set(false)
            try {
                jobFinished(params, reschedule)
            } catch (_: Throwable) {
                // jobFinished after a stopped job is tolerated by the platform; never crash here.
            }
        }
    }

    companion object {
        /**
         * Stable job id used by [TvThreatIntelRepository] to schedule and cancel the periodic sync.
         * Do not change without migrating persisted jobs.
         */
        const val JOB_ID = TvThreatIntelRepository.THREAT_INTEL_JOB_ID
    }
}
