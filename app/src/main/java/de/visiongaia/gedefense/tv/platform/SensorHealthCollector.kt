package de.visiongaia.gedefense.tv.platform

import android.app.AppOpsManager
import android.content.Context
import android.os.Process
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.EvidenceHealth
import de.visiongaia.gedefense.tv.core.model.Finding
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TvEvent

/**
 * App-health collector (datasheet event class TV_SENSOR_HEALTH).
 *
 * Reports the capability/permission state of the app's own optional and required sensors instead of
 * pretending a missing permission is a device finding. Optional sensors that V1 deliberately does not
 * request (usage access) are reported as "not enabled", never as a gap or a vulnerability.
 */
class SensorHealthCollector(
    context: Context,
    private val evidenceProbe: () -> EvidenceHealth,
) : TvCollector {
    private val appContext = context.applicationContext

    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "sensor-health",
        category = CollectorCategory.SENSOR_HEALTH,
        titleKey = "collector.sensorhealth.title",
        descriptionKey = "collector.sensorhealth.description",
        restrictedOnSomeDevices = false,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    @Volatile
    var lastProbes: List<SensorProbe> = emptyList()
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        return try {
            if (cancel.isCancelled()) throw InterruptedException("sensor health collector cancelled")
            val collectedAt = System.currentTimeMillis()
            val internetGranted = CollectorSupport.isPermissionGranted(appContext, android.Manifest.permission.INTERNET)
            val networkStateGranted = CollectorSupport.isPermissionGranted(
                appContext,
                android.Manifest.permission.ACCESS_NETWORK_STATE,
            )
            val usageAccess = usageAccessState()
            val evidenceHealth = try {
                evidenceProbe()
            } catch (_: Throwable) {
                EvidenceHealth.UNAVAILABLE
            }

            val probes = listOf(
                SensorProbe(
                    name = "internet_permission",
                    required = true,
                    ok = internetGranted,
                    reasonKey = if (internetGranted) null else CollectorSupport.KEY_COLLECTOR_PERMISSION_REQUIRED,
                ),
                SensorProbe(
                    name = "network_state_permission",
                    required = true,
                    ok = networkStateGranted,
                    reasonKey = if (networkStateGranted) null else CollectorSupport.KEY_COLLECTOR_PERMISSION_REQUIRED,
                ),
                SensorProbe(
                    name = "evidence_ledger",
                    required = true,
                    ok = evidenceHealth.healthy,
                    reasonKey = evidenceHealth.reason?.key ?: "evidence.unavailable",
                ),
                SensorProbe(
                    name = "usage_access",
                    required = false,
                    ok = usageAccess == USAGE_ALLOWED,
                    reasonKey = "usage_access.$usageAccess",
                ),
                SensorProbe(
                    name = "vpn_inspector",
                    required = false,
                    // V1 intentionally does not use VpnService; reporting it as a gap would be false.
                    ok = false,
                    reasonKey = "usage_access.not_implemented",
                ),
            )
            lastProbes = probes

            val findings = ArrayList<Finding>(2)
            val evidence = CollectorSupport.evidence(descriptor.id, collectedAt)
            for (probe in probes) {
                if (!probe.required || probe.ok) continue
                if (probe.name == "evidence_ledger") {
                    findings.add(
                        infraFinding(
                            ruleId = RULE_EVIDENCE,
                            probe = probe,
                            titleKey = "sensor.evidence.title",
                            whyKey = "sensor.evidence.why",
                            atMillis = collectedAt,
                            evidence = evidence,
                        ),
                    )
                } else {
                    findings.add(
                        infraFinding(
                            ruleId = RULE_REQUIRED,
                            probe = probe,
                            titleKey = "sensor.permission.title",
                            whyKey = "sensor.permission.why",
                            atMillis = collectedAt,
                            evidence = evidence,
                        ),
                    )
                }
            }

            val degradedRequired = probes.count { it.required && !it.ok }
            val completedAt = System.currentTimeMillis()
            lastEvents = listOfNotNull(
                CollectorSupport.event(
                    eventClass = EventClass.TV_SENSOR_HEALTH,
                    collectorId = descriptor.id,
                    deviceId = environment.deviceId,
                    osApiLevel = environment.platform.sdkInt,
                    eventTimeMillis = completedAt,
                    subject = "sensor-health",
                    dataQuality = DataQuality.FRESH,
                    attributes = mapOf(
                        "probes" to probes.size.toString(),
                        "degraded_required" to degradedRequired.toString(),
                        "optional_not_enabled" to probes.count { !it.required && !it.ok }.toString(),
                        "internet_permission" to internetGranted.toString(),
                        "network_state_permission" to networkStateGranted.toString(),
                        "usage_access" to usageAccess,
                        "evidence_healthy" to evidenceHealth.healthy.toString(),
                        "evidence_records" to evidenceHealth.records.toString(),
                    ),
                ),
            )
            CollectorSupport.supported(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = completedAt,
                visibility = if (degradedRequired == 0) DataVisibility.FULL else DataVisibility.PARTIAL,
                dataQuality = DataQuality.FRESH,
                findings = findings,
                coverage = CollectorCoverage(observed = probes.size, total = probes.size),
            )
        } catch (interrupted: InterruptedException) {
            throw interrupted
        } catch (_: Throwable) {
            CollectorSupport.failed(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = System.currentTimeMillis(),
            )
        }
    }

    private fun infraFinding(
        ruleId: String,
        probe: SensorProbe,
        titleKey: String,
        whyKey: String,
        evidence: de.visiongaia.gedefense.tv.core.model.EvidenceRef,
        atMillis: Long,
    ): Finding = Finding(
        id = Finding.identity(ruleId, probe.name),
        ruleId = ruleId,
        severity = Severity.LOW,
        confidence = Confidence.HIGH,
        category = CollectorCategory.SENSOR_HEALTH,
        title = MessageRef(titleKey, listOf(probe.name)),
        why = MessageRef(whyKey, listOf(probe.name, probe.reasonKey ?: "unknown")),
        component = probe.name,
        evidence = evidence,
        recommendation = MessageRef("sensor.permission.recommendation"),
        visibility = DataVisibility.PARTIAL,
        firstSeenMillis = atMillis,
        lastSeenMillis = atMillis,
        policyAction = PolicyAction.OBSERVE,
    )

    private fun usageAccessState(): String = try {
        val appOps = appContext.getSystemService(Context.APP_OPS_SERVICE) as? AppOpsManager
        if (appOps == null) {
            USAGE_UNKNOWN
        } else {
            when (
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    Process.myUid(),
                    appContext.packageName,
                )
            ) {
                AppOpsManager.MODE_ALLOWED -> USAGE_ALLOWED
                AppOpsManager.MODE_IGNORED, AppOpsManager.MODE_ERRORED -> USAGE_NOT_ENABLED
                AppOpsManager.MODE_DEFAULT -> USAGE_NOT_REQUESTED
                else -> USAGE_UNKNOWN
            }
        }
    } catch (_: Throwable) {
        USAGE_UNKNOWN
    }

    data class SensorProbe(
        val name: String,
        val required: Boolean,
        val ok: Boolean,
        val reasonKey: String?,
    )

    companion object {
        private const val USAGE_ALLOWED = "allowed"
        private const val USAGE_NOT_ENABLED = "not_enabled"
        private const val USAGE_NOT_REQUESTED = "not_requested"
        private const val USAGE_UNKNOWN = "unknown"
        private const val RULE_REQUIRED = "sensor-health-required"
        private const val RULE_EVIDENCE = "sensor-evidence-required"
    }
}
