package de.visiongaia.gedefense.tv

import android.content.Context
import de.visiongaia.gedefense.tv.contract.EvidenceApi
import de.visiongaia.gedefense.tv.contract.ReportApi
import de.visiongaia.gedefense.tv.contract.ScanControllerApi
import de.visiongaia.gedefense.tv.contract.SettingsApi
import de.visiongaia.gedefense.tv.contract.ThreatIntelApi
import de.visiongaia.gedefense.tv.core.model.TextCatalog

/**
 * Process-wide service container for the TV app. Populated exactly once by
 * [de.visiongaia.gedefense.tv.data.TvServicesBootstrap] from [TvApplication].
 *
 * UI code must use [get] and depend on the contract interfaces only. Tests may install a fake
 * container through [installForTest].
 */
class TvServices private constructor(
    val appContext: Context,
    val catalog: TextCatalog,
    val settings: SettingsApi,
    val deviceId: String,
    val appVersionName: String,
    val appVersionCode: Long,
    val scan: ScanControllerApi,
    val evidence: EvidenceApi,
    val threatIntel: ThreatIntelApi,
    val reports: ReportApi,
    val vpn: de.visiongaia.gedefense.tv.contract.VpnControlApi,
    val traffic: de.visiongaia.gedefense.tv.contract.TrafficApi,
    val xdr: de.visiongaia.gedefense.tv.contract.XdrApi,
    val anomaly: de.visiongaia.gedefense.tv.contract.AnomalyApi,
    val containment: de.visiongaia.gedefense.tv.contract.ContainmentApi,
) {
    companion object {
        @Volatile
        private var instance: TvServices? = null

        fun get(context: Context): TvServices {
            instance?.let { return it }
            synchronized(this) {
                instance?.let { return it }
                error("TvServices not initialised - application startup failed")
            }
        }

        internal fun install(services: TvServices) {
            synchronized(this) {
                check(instance == null) { "TvServices already installed" }
                instance = services
            }
        }

        fun createForTest(
            appContext: Context,
            catalog: TextCatalog,
            settings: SettingsApi,
            deviceId: String,
            appVersionName: String,
            appVersionCode: Long,
            scan: ScanControllerApi,
            evidence: EvidenceApi,
            threatIntel: ThreatIntelApi,
            reports: ReportApi,
            vpn: de.visiongaia.gedefense.tv.contract.VpnControlApi,
            traffic: de.visiongaia.gedefense.tv.contract.TrafficApi,
            xdr: de.visiongaia.gedefense.tv.contract.XdrApi,
            anomaly: de.visiongaia.gedefense.tv.contract.AnomalyApi,
            containment: de.visiongaia.gedefense.tv.contract.ContainmentApi,
        ): TvServices = TvServices(
            appContext = appContext,
            catalog = catalog,
            settings = settings,
            deviceId = deviceId,
            appVersionName = appVersionName,
            appVersionCode = appVersionCode,
            scan = scan,
            evidence = evidence,
            threatIntel = threatIntel,
            reports = reports,
            vpn = vpn,
            traffic = traffic,
            xdr = xdr,
            anomaly = anomaly,
            containment = containment,
        )
    }
}
