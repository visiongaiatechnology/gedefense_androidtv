package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.content.pm.PackageManager
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.report.DefaultReportRenderer
import de.visiongaia.gedefense.tv.core.text.DeCatalog
import de.visiongaia.gedefense.tv.ui.text.ResourceTextCatalog
import de.visiongaia.gedefense.tv.geo.TvGeoLookup
import de.visiongaia.gedefense.tv.geo.TvGeoRepository
import de.visiongaia.gedefense.tv.scan.DefaultScanController
import de.visiongaia.gedefense.tv.traffic.TvTrafficStore
import de.visiongaia.gedefense.tv.vpn.NativeGaiaNet
import de.visiongaia.gedefense.tv.vpn.TvVpnController

/**
 * Builds and installs the process-wide [TvServices] container exactly once.
 *
 * Called from `TvApplication.onCreate` (Lead-owned). The container is returned as well so tests and
 * application code can hold a reference without a second lookup. Construction is intentionally cheap
 * and main-thread safe: Keystore work, feed cache loading and job scheduling are moved to the
 * background warm-up pipelines of the individual repositories.
 */
object TvServicesBootstrap {
    fun create(context: Context): TvServices {
        val appContext = context.applicationContext
        synchronized(this) {
            existing(appContext)?.let { return it }
            val settings = TvSettingsStore(appContext)
            val deviceId = settings.ensureDeviceId()
            val appVersionName = appVersionName(appContext)
            val appVersionCode = appVersionCode(appContext)
            val evidence = TvEvidenceRepository(appContext)
            // Serialize the cold Android Keystore path: the feed cache must not run opaque-provider
            // operations while evidence key custody / ledger verification is still initializing.
            val policyBridge =
                java.util.concurrent.atomic.AtomicReference<((de.visiongaia.gedefense.mobile.core.ThreatIndex) -> Unit)?>(null)
            val threatIntel = TvThreatIntelRepository(appContext, settings, { evidence.awaitStartup() }) { index ->
                try {
                    policyBridge.get()?.invoke(index)
                } catch (_: Throwable) {
                    // Policy handover after sync is best effort; the next start/refresh retries it.
                }
            }
            val reports = TvReportExporter(
                context = appContext,
                catalog = ResourceTextCatalog(appContext),
                renderer = DefaultReportRenderer,
                evidence = evidence,
                threatIntel = threatIntel,
                deviceId = deviceId,
            )
            val scan = DefaultScanController(
                context = appContext,
                settings = settings,
                deviceId = deviceId,
                evidence = evidence,
                threatIntel = threatIntel,
            )
            // V2 data plane: offline geo lookup, bounded traffic store, XDR adapter and loopback VPN
            // controller. The GaiaNet helper is only registered here (file validation/stat); no
            // process is started before user consent.
            val geoRepository = TvGeoRepository(appContext) { TvKeyCustody.cached()?.geoHmac }
            val traffic = TvTrafficStore(appContext, geoLookup = TvGeoLookup(geoRepository))
            val xdr = TvXdrStore()
            xdr.attach(traffic)
            val anomaly = TvAnomalyStore()
            anomaly.attach(traffic)
            val vpn = TvVpnController(appContext, settings, traffic)
            val containment = TvContainmentStore(
                settings = settings,
                vpn = vpn,
                anomaliesProvider = { anomaly.anomalies() },
                baseIndexProvider = {
                    threatIntel.policyIndexSnapshot() ?: de.visiongaia.gedefense.mobile.core.ThreatIndex.empty()
                },
                evidenceSink = { type, severity, subject, detail ->
                    evidence.recordSecurityEvent(type, severity, subject, detail)
                },
            )
            policyBridge.set { index ->
                xdr.setThreatIndex(index)
                anomaly.setThreatIndex(index)
                // The containment store owns the composed VPN policy (base + active overlay); a direct
                // vpn.setThreatIndex(base) here would drop active containments on every TI sync.
                containment.updateBaseThreatIndex(index)
            }
            NativeGaiaNet.initialize(appContext)
            val services = TvServices.createForTest(
                appContext = appContext,
                catalog = ResourceTextCatalog(appContext),
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
            TvServices.install(services)
            containment.start()
            scheduleV2Startup(appContext, settings, vpn, threatIntel, xdr, containment, geoRepository) {
                evidence.awaitStartup()
            }
            return services
        }
    }

    /**
     * Background V2 startup: load the cached offline geo table, hand the validated threat index to the
     * VPN/XDR policy context, then (only when the user enabled auto-start and finished onboarding)
     * attempt a consent-free VPN start. A geo refresh runs on its own low-priority thread because the
     * upstream CSV downloads are large; until it succeeds the map honestly reports unknown countries.
     * Nothing here runs on the main thread.
     */
    private fun scheduleV2Startup(
        appContext: Context,
        settings: TvSettingsStore,
        vpn: TvVpnController,
        threatIntel: TvThreatIntelRepository,
        xdr: TvXdrStore,
        containment: TvContainmentStore,
        geoRepository: TvGeoRepository,
        awaitKeyCustody: () -> Boolean,
    ) {
        try {
            java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "gedefense-tv-v2-startup").apply {
                    isDaemon = true
                    priority = Thread.MIN_PRIORITY
                }
            }.execute {
                // The geo integrity key lives in the same keyring as the evidence/TI subkeys.
                try {
                    awaitKeyCustody()
                } catch (_: Throwable) {
                    // Key custody unavailable: geo and policy stay honestly unavailable.
                }
                val geoState = try {
                    geoRepository.loadCached()
                } catch (_: Throwable) {
                    null
                }
                if (geoState == null || !geoState.ready || geoState.fetchedAtMillis <= 0L ||
                    System.currentTimeMillis() - geoState.fetchedAtMillis >= GEO_REFRESH_HINT_MILLIS
                ) {
                    scheduleGeoRefresh(geoRepository)
                }
                try {
                    val index = threatIntel.policyIndexSnapshot()
                    xdr.setThreatIndex(index)
                    // Route the base policy through containment: it composes base + active overlay and
                    // pushes the resulting policy to the VPN controller on this background thread.
                    containment.updateBaseThreatIndex(index)
                } catch (_: Throwable) {
                    // An empty/unavailable policy context stays honest: privacy/tracker policy only.
                }
                val eligible = try {
                    settings.vpnAutoStart() && settings.protectionSetupDone()
                } catch (_: Throwable) {
                    false
                }
                if (!eligible) return@execute
                try {
                    vpn.startIfPermitted(object : de.visiongaia.gedefense.tv.contract.VpnStateListener {
                        override fun onStateChanged(status: de.visiongaia.gedefense.tv.core.model.VpnStatus) {
                            // Status changes are surfaced through TvVpnProcessState / the UI.
                        }
                    })
                } catch (_: Throwable) {
                    // Auto-start is best effort; the protection screen can always start it manually.
                }
            }
        } catch (_: Throwable) {
            // Thread creation failure must never affect app startup.
        }
    }

    /** Dedicated low-priority geo refresh; failures keep the last-known-good table (or UNKNOWN). */
    private fun scheduleGeoRefresh(geoRepository: TvGeoRepository) {
        try {
            java.util.concurrent.Executors.newSingleThreadExecutor { runnable ->
                Thread(runnable, "gedefense-tv-geo-sync").apply {
                    isDaemon = true
                    priority = Thread.MIN_PRIORITY
                }
            }.execute {
                try {
                    geoRepository.syncDue()
                } catch (_: Throwable) {
                    // Honest fallback: the traffic map stays "ZZ"/unknown until a later refresh works.
                }
            }
        } catch (_: Throwable) {
            // Geo enrichment is optional; never affect app startup.
        }
    }

    private fun existing(appContext: Context): TvServices? = try {
        TvServices.get(appContext)
    } catch (_: IllegalStateException) {
        null
    }

    private fun appVersionName(context: Context): String = try {
        context.packageManager.getPackageInfo(context.packageName, 0).versionName?.takeIf { it.isNotBlank() }
            ?: FALLBACK_VERSION
    } catch (_: PackageManager.NameNotFoundException) {
        FALLBACK_VERSION
    }

    private fun appVersionCode(context: Context): Long = try {
        val info = context.packageManager.getPackageInfo(context.packageName, 0)
        if (android.os.Build.VERSION.SDK_INT >= 28) {
            info.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            info.versionCode.toLong()
        }
    } catch (_: PackageManager.NameNotFoundException) {
        0L
    }

    private const val FALLBACK_VERSION = "0.1.0-alpha1"
    private const val GEO_REFRESH_HINT_MILLIS = 7L * 24L * 60L * 60L * 1_000L
}
