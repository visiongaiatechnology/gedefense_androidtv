package de.visiongaia.gedefense.tv.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import de.visiongaia.gedefense.tv.R
import de.visiongaia.gedefense.tv.TvMainActivity
import de.visiongaia.gedefense.tv.TvServices
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.core.model.VpnState
import de.visiongaia.gedefense.tv.core.model.VpnStatus
import de.visiongaia.gedefense.tv.data.TvSettingsStore
import de.visiongaia.gedefense.tv.data.TvThreatIntelRepository
import de.visiongaia.gedefense.tv.traffic.TvTrafficStore
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * On-device loopback VPN service (V2, DIRECT egress only).
 *
 * Full-flow TUN (`10.253.0.2/32`, `fd7a:4744::2/128`, MTU [MTU]) routes all traffic through the
 * vendored GaiaNet helper, which filters by the authenticated threat index and the immutable privacy
 * policy. The own package is excluded so the helper's upstream sockets cannot recurse.
 *
 * Fail-closed contract:
 *  - the established TUN descriptor is never closed because the helper failed; it stays as an anchor
 *    that drops/backpressures traffic (no direct-routing window) while a bounded backoff retries;
 *  - [VpnStatus] is only ACTIVE when the helper acknowledged startup and telemetry is attached;
 *  - loss of the telemetry channel or the helper downgrades to DEGRADED and re-establishes a new
 *    anchor before retrying;
 *  - an explicit stop or `onRevoke` tears the tunnel down and reports OFF.
 */
class TvVpnService : VpnService() {
    private val control = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-vpn-control").apply { isDaemon = true }
    }
    private val retryScheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor { runnable ->
        Thread(runnable, "gedefense-tv-vpn-retry").apply { isDaemon = true }
    }
    private val destroyed = AtomicBoolean(false)
    private val running = AtomicBoolean(false)
    private val lock = Any()

    private var connectivity: ConnectivityManager? = null
    private var powerManager: PowerManager? = null
    private var settingsStore: TvSettingsStore? = null
    private var trafficStore: TvTrafficStore? = null
    private lateinit var privacyIntelligence: TvPrivacyIntelligence
    private val physicalNetworks = LinkedHashMap<Network, NetworkCapabilities>()
    private val networkLock = Any()

    private var tunnel: ParcelFileDescriptor? = null
    private var session: NativeGaiaNet.Session? = null
    private var telemetry: TvFlowTelemetryReader? = null
    private var retryAttempt = 0
    private var retryScheduled = false

    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) = updatePhysicalNetwork(network, null)

        override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) =
            updatePhysicalNetwork(network, networkCapabilities)

        override fun onLost(network: Network) {
            synchronized(networkLock) { physicalNetworks.remove(network) }
            applyUnderlyingNetworks()
        }
    }

    private val powerReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            updatePowerConstrained()
        }
    }

    override fun onCreate() {
        super.onCreate()
        privacyIntelligence = TvPrivacyIntelligence(applicationContext)
        connectivity = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        powerManager = getSystemService(Context.POWER_SERVICE) as? PowerManager
        createChannel()
        registerPhysicalNetworkObserver()
        registerPowerObserver()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                submitControl { stopProtection(reason = "operator_stop") }
                return START_NOT_STICKY
            }
            ACTION_REFRESH -> {
                submitControl { refreshTransport() }
                return START_STICKY
            }
            else -> {
                startAsForeground(getString(R.string.v2_vpn_notification_starting))
                submitControl { startProtection() }
                return START_STICKY
            }
        }
    }

    override fun onRevoke() {
        submitControl { stopProtection(reason = "system_revoke") }
        super.onRevoke()
    }

    override fun onDestroy() {
        destroyed.set(true)
        try {
            connectivity?.unregisterNetworkCallback(networkCallback)
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
        try {
            unregisterReceiver(powerReceiver)
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
        retryScheduler.shutdownNow()
        control.shutdownNow()
        synchronized(lock) {
            telemetry?.close()
            telemetry = null
            session?.close()
            session = null
            tunnel?.closeSafely()
            tunnel = null
        }
        running.set(false)
        val current = TvVpnProcessState.status().state
        if (current == VpnState.PREPARING || current == VpnState.ACTIVE || current == VpnState.DEGRADED) {
            // Only a once-active/starting session degrades to OFF on teardown; FAILED/UNSUPPORTED
            // must stay visible as the honest outcome instead of being masked by a late OFF.
            TvVpnProcessState.publish(VpnStatus.OFF)
        }
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = super.onBind(intent)

    // --------------------------------------------------------------- start / stop

    private fun submitControl(action: () -> Unit): Boolean {
        if (destroyed.get()) return false
        return try {
            control.execute {
                if (!destroyed.get()) action()
            }
            true
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun startProtection() {
        if (running.get()) return
        val services = try {
            TvServices.get(applicationContext)
        } catch (_: Throwable) {
            null
        }
        if (services == null) {
            publishFailed("vpn_services_unavailable")
            return
        }
        settingsStore = services.settings as? TvSettingsStore ?: TvSettingsStore(this)
        trafficStore = services.traffic as? TvTrafficStore
        if (trafficStore == null) {
            publishFailed("vpn_traffic_unavailable")
            return
        }
        if (VpnService.prepare(this) != null) {
            // Consent was revoked after the controller checked it; never start an unapproved VPN.
            publishFailed("vpn_consent_required")
            return
        }
        if (!NativeGaiaNet.available) {
            TvVpnProcessState.publish(
                VpnStatus(
                    state = VpnState.UNSUPPORTED,
                    startedAtMillis = 0L,
                    reasonKey = "vpn_helper_unavailable",
                    privacyProfile = profileKey(),
                ),
            )
            stopSelfSafely()
            return
        }
        running.set(true)
        retryAttempt = 0
        Log.i(TAG, "VPN start requested (privacy profile=${profileKey()})")
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.PREPARING,
                startedAtMillis = 0L,
                privacyProfile = profileKey(),
            ),
        )
        updateNotification(getString(R.string.v2_vpn_notification_starting))
        try {
            if (tunnel == null) {
                val established = establishTunnel()
                if (established == null) {
                    publishFailed("vpn_establish_failed")
                    return
                }
                tunnel = established
            }
            startHelper()
        } catch (error: Throwable) {
            Log.w(TAG, "VPN start failed type=${error::class.java.simpleName}")
            publishFailed("vpn_start_failed")
        }
    }

    private fun establishTunnel(): ParcelFileDescriptor? {
        val builder = try {
            Builder()
                .setSession(getString(R.string.v2_vpn_session_name))
                .setMtu(MTU)
                .setBlocking(true)
                .also { if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) it.setMetered(false) }
        } catch (_: RuntimeException) {
            return null
        }
        try {
            // Self-bypass: helper upstream sockets share our UID and must not be recaptured.
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
            return null
        }
        try {
            builder.addAddress(IPV4_ADDRESS, 32)
            builder.addAddress(IPV6_ADDRESS, 128)
            builder.addRoute("0.0.0.0", 0)
            builder.addRoute("::", 0)
        } catch (_: RuntimeException) {
            return null
        }
        // Route the system resolver through the TUN so the helper can inspect/block DNS queries.
        // Without an explicit VPN DNS server, Android would keep using the underlay resolver and
        // tracker telemetry would never be filterable.
        try {
            val dnsServers = activeDnsServers()
            if (dnsServers.isEmpty()) {
                builder.addDnsServer("1.1.1.1")
            } else {
                dnsServers.forEach { builder.addDnsServer(it) }
            }
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
        val underlays = underlyingNetworkArray()
        if (underlays.isNotEmpty()) {
            try {
                builder.setUnderlyingNetworks(underlays)
            } catch (error: RuntimeException) {
                RuntimeFailureLog.nonCritical("tv-vpn-service", error)
            }
        }
        try {
            builder.setConfigureIntent(
                PendingIntent.getActivity(
                    this,
                    0,
                    Intent(this, TvMainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
                ),
            )
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
        return try {
            builder.establish()
        } catch (error: RuntimeException) {
            Log.w(TAG, "tunnel establish failed type=${error::class.java.simpleName}")
            null
        }
    }

    private fun activeDnsServers(): List<java.net.InetAddress> {
        return try {
            val manager = connectivity ?: (getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager) ?: return emptyList()
            val network = manager.activeNetwork ?: return emptyList()
            val properties: android.net.LinkProperties = manager.getLinkProperties(network) ?: return emptyList()
            properties.dnsServers.distinct()
        } catch (_: RuntimeException) {
            emptyList()
        }
    }

    private fun startHelper() {
        val anchor = tunnel
        if (anchor == null) {
            publishFailed("vpn_anchor_missing")
            return
        }
        val services = try {
            TvServices.get(applicationContext)
        } catch (_: Throwable) {
            null
        }
        if (services == null) {
            publishFailed("vpn_services_unavailable")
            return
        }
        val index = TvVpnProcessState.threatIndex.takeIf { it.count > 0 }
            ?: (services.threatIntel as? TvThreatIntelRepository)?.policyIndexSnapshot()
            ?: ThreatIndex.empty()
        val profile = settingsStore?.privacyProfile() ?: TvPrivacyProfile.BALANCED
        if (index.count == 0) {
            // Honest degraded state: privacy/tracker filtering works, but the TI-based C2 layer is
            // missing until a successful sync delivers a non-empty signed index.
            Log.w(TAG, "VPN starts with an empty threat index; privacy/tracker policy only (degraded)")
        }
        val started = NativeGaiaNet.start(
            context = this,
            tunnel = anchor,
            index = index,
            privacyRegistry = privacyIntelligence.registry(profile),
            privacyProfile = profile.toCoreProfile(),
            cacheDir = cacheDir,
            powerConstrained = isPowerConstrained(),
            telemetryDetailed = settingsStore?.detailedTelemetryEnabled() ?: false,
        )
        if (started == null) {
            onHelperFailure()
            return
        }
        synchronized(lock) {
            session = started
            tunnel = null // Ownership of the TUN descriptor moved into the helper session anchor.
            telemetry = TvFlowTelemetryReader(
                context = this,
                descriptor = started.telemetryRead,
                store = trafficStore ?: return@synchronized,
                privacy = privacyIntelligence,
                settings = settingsStore ?: TvSettingsStore(this),
                onFatal = { reason ->
                    submitControl { handleTelemetryFatal(reason) }
                },
            )
        }
        retryAttempt = 0
        retryScheduled = false
        trafficStore?.beginSession()
        val tiAvailable = index.count > 0
        val activeState = if (tiAvailable) VpnState.ACTIVE else VpnState.DEGRADED
        Log.i(TAG, "VPN state=${activeState.name} threatRecords=${index.count} freshAnchor=true")
        TvVpnProcessState.publish(
            VpnStatus(
                state = activeState,
                startedAtMillis = System.currentTimeMillis(),
                reasonKey = if (tiAvailable) null else "vpn_policy_partial_ti_unavailable",
                privacyProfile = profileKey(),
            ),
        )
        updateNotification(
            getString(
                if (tiAvailable) R.string.v2_vpn_notification_active else R.string.v2_vpn_notification_degraded,
            ),
        )
    }

    private fun onHelperFailure() {
        retryAttempt++
        val reason = "vpn_helper_" + (NativeGaiaNet.lastStartFailure ?: "start_failed")
        Log.w(TAG, "VPN helper failure attempt=$retryAttempt reason=${NativeGaiaNet.lastStartFailure ?: "unknown"}")
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.DEGRADED,
                startedAtMillis = 0L,
                reasonKey = reason.take(120),
                privacyProfile = profileKey(),
            ),
        )
        updateNotification(getString(R.string.v2_vpn_notification_degraded))
        if (tunnel == null) {
            // No anchor means no capture at all: fail honestly instead of pretending to protect.
            val reestablished = establishTunnel()
            if (reestablished == null) {
                publishFailed("vpn_anchor_lost")
                return
            }
            tunnel = reestablished
        }
        scheduleRetry()
    }

    private fun handleTelemetryFatal(reason: String) {
        if (!running.get() || destroyed.get()) return
        trafficStore?.endSession()
        synchronized(lock) {
            telemetry?.close()
            telemetry = null
            session?.close()
            session = null
        }
        Log.w(TAG, "VPN telemetry degraded reason=${reason.take(64)}")
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.DEGRADED,
                startedAtMillis = 0L,
                reasonKey = if (reason == "fullflow_telemetry_eof") "vpn_helper_exited" else "vpn_telemetry_failed",
                privacyProfile = profileKey(),
            ),
        )
        updateNotification(getString(R.string.v2_vpn_notification_degraded))
        if (tunnel == null) {
            val reestablished = establishTunnel()
            if (reestablished == null) {
                publishFailed("vpn_anchor_lost")
                return
            }
            tunnel = reestablished
        }
        retryAttempt++
        scheduleRetry()
    }

    private fun scheduleRetry() {
        if (retryScheduled || !running.get()) return
        if (retryAttempt > MAX_RETRY_ATTEMPTS) {
            publishFailed("vpn_helper_unavailable")
            return
        }
        retryScheduled = true
        val delay = retryDelayMillis(retryAttempt)
        try {
            retryScheduler.schedule({
                retryScheduled = false
                submitControl {
                    if (!running.get()) return@submitControl
                    try {
                        if (tunnel == null) {
                            val reestablished = establishTunnel()
                            if (reestablished == null) {
                                publishFailed("vpn_anchor_lost")
                                return@submitControl
                            }
                            tunnel = reestablished
                        }
                        startHelper()
                    } catch (error: Throwable) {
                        Log.w(TAG, "VPN retry failed type=${error::class.java.simpleName}")
                        onHelperFailure()
                    }
                }
            }, delay, TimeUnit.MILLISECONDS)
        } catch (_: RuntimeException) {
            retryScheduled = false
        }
    }

    private fun refreshTransport() {
        if (!running.get()) return
        val candidate = establishTunnel() ?: return
        synchronized(lock) {
            telemetry?.close()
            telemetry = null
            session?.close()
            session = null
            tunnel?.closeSafely()
            tunnel = candidate
        }
        retryAttempt = 0
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.PREPARING,
                startedAtMillis = 0L,
                reasonKey = "vpn_policy_refresh",
                privacyProfile = profileKey(),
            ),
        )
        startHelper()
    }

    private fun stopProtection(reason: String) {
        Log.i(TAG, "VPN stop reason=${reason.take(48)}")
        running.set(false)
        retryAttempt = 0
        retryScheduled = false
        try {
            retryScheduler.shutdownNow()
        } catch (_: RuntimeException) {
            // Retry scheduler teardown is best effort.
        }
        trafficStore?.endSession()
        synchronized(lock) {
            telemetry?.close()
            telemetry = null
            session?.close()
            session = null
            tunnel?.closeSafely()
            tunnel = null
        }
        NativeGaiaNet.stop()
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.OFF,
                startedAtMillis = 0L,
                reasonKey = reason.take(120),
                privacyProfile = profileKey(),
            ),
        )
        updateNotification(getString(R.string.v2_vpn_notification_stopped))
        stopForegroundCompat()
        stopSelfSafely()
    }

    private fun publishFailed(reason: String) {
        running.set(false)
        Log.w(TAG, "VPN failed reason=${reason.take(64)}; keeping fail-closed TUN anchor")
        TvVpnProcessState.publish(
            VpnStatus(
                state = VpnState.FAILED,
                startedAtMillis = 0L,
                reasonKey = reason.take(120),
                privacyProfile = profileKey(),
            ),
        )
        // SECV2-02: never tear down the established anchor on a helper failure. The TUN keeps
        // dropping/backpressuring traffic (fail-closed); the foreground service stays alive so the
        // user sees an explicit failed state and can stop/retry it from the protection dashboard.
        updateNotification(getString(R.string.v2_vpn_notification_degraded))
    }

    private fun stopSelfSafely() {
        try {
            stopSelf()
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    // -------------------------------------------------------------- notifications

    private fun createChannel() {
        try {
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    getString(R.string.v2_vpn_channel_name),
                    NotificationManager.IMPORTANCE_LOW,
                ).apply {
                    description = getString(R.string.v2_vpn_channel_desc)
                    setShowBadge(false)
                },
            )
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun buildNotification(text: String): Notification {
        val contentIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, TvMainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setSmallIcon(android.R.drawable.stat_sys_warning)
            .setContentTitle(getString(R.string.v2_vpn_notification_title))
            .setContentText(text)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
            .setContentIntent(contentIntent)
            .build()
    }

    private fun startAsForeground(text: String) {
        try {
            startForeground(NOTIFICATION_ID, buildNotification(text))
        } catch (error: RuntimeException) {
            Log.w(TAG, "startForeground failed type=${error::class.java.simpleName}")
        }
    }

    private fun updateNotification(text: String) {
        try {
            val manager = getSystemService(NotificationManager::class.java)
            manager.notify(NOTIFICATION_ID, buildNotification(text))
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun stopForegroundCompat() {
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    // -------------------------------------------------------------- network + power

    private fun registerPhysicalNetworkObserver() {
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            connectivity?.registerNetworkCallback(request, networkCallback)
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun updatePhysicalNetwork(network: Network, provided: NetworkCapabilities?) {
        val caps = provided ?: try {
            connectivity?.getNetworkCapabilities(network)
        } catch (_: RuntimeException) {
            null
        } ?: return
        if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)) return
        synchronized(networkLock) {
            if (physicalNetworks.size >= MAX_PHYSICAL_NETWORKS && network !in physicalNetworks) {
                physicalNetworks.entries.firstOrNull()?.let { physicalNetworks.remove(it.key) }
            }
            physicalNetworks[network] = caps
        }
        applyUnderlyingNetworks()
    }

    private fun underlyingNetworkArray(): Array<Network> = synchronized(networkLock) {
        physicalNetworks.entries.asSequence()
            .filter { (_, caps) -> caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) }
            .sortedByDescending { (_, caps) -> physicalNetworkScore(caps) }
            .map { it.key }
            .take(MAX_PHYSICAL_NETWORKS)
            .toList()
            .toTypedArray()
    }

    private fun applyUnderlyingNetworks() {
        val networks = underlyingNetworkArray()
        try {
            setUnderlyingNetworks(networks.takeIf { it.isNotEmpty() })
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun physicalNetworkScore(caps: NetworkCapabilities): Int =
        (if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)) 100 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)) 30 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) 20 else 0) +
            (if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) 10 else 0)

    private fun registerPowerObserver() {
        val filter = IntentFilter().apply {
            addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
            addAction(PowerManager.ACTION_POWER_SAVE_MODE_CHANGED)
            addAction(Intent.ACTION_SCREEN_ON)
            addAction(Intent.ACTION_SCREEN_OFF)
        }
        try {
            if (Build.VERSION.SDK_INT >= 33) {
                registerReceiver(powerReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
            } else {
                @Suppress("DEPRECATION")
                registerReceiver(powerReceiver, filter)
            }
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun isPowerConstrained(): Boolean {
        val manager = powerManager ?: return false
        return try {
            manager.isDeviceIdleMode || manager.isPowerSaveMode || !manager.isInteractive
        } catch (_: RuntimeException) {
            false
        }
    }

    private fun updatePowerConstrained() {
        val constrained = isPowerConstrained()
        try {
            NativeGaiaNet.setPowerConstrained(constrained)
        } catch (error: RuntimeException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    private fun retryDelayMillis(attempt: Int): Long =
        (RETRY_BASE_DELAY_MILLIS shl (attempt - 1).coerceIn(0, 5)).coerceAtMost(RETRY_MAX_DELAY_MILLIS)

    private fun profileKey(): String = when (settingsStore?.privacyProfile() ?: TvPrivacyProfile.BALANCED) {
        TvPrivacyProfile.OFF -> "off"
        TvPrivacyProfile.CONSERVATIVE -> "conservative"
        TvPrivacyProfile.BALANCED -> "balanced"
        TvPrivacyProfile.STRICT -> "strict"
    }

    private fun TvPrivacyProfile?.toCoreProfile(): PrivacyProfile = when (this) {
        TvPrivacyProfile.OFF -> PrivacyProfile.OFF
        TvPrivacyProfile.CONSERVATIVE -> PrivacyProfile.CONSERVATIVE
        TvPrivacyProfile.STRICT -> PrivacyProfile.STRICT
        else -> PrivacyProfile.BALANCED
    }

    private fun ParcelFileDescriptor.closeSafely() {
        try {
            close()
        } catch (error: java.io.IOException) {
            RuntimeFailureLog.nonCritical("tv-vpn-service", error)
        }
    }

    companion object {
        const val ACTION_START = "de.visiongaia.gedefense.tv.vpn.action.START"
        const val ACTION_STOP = "de.visiongaia.gedefense.tv.vpn.action.STOP"
        const val ACTION_REFRESH = "de.visiongaia.gedefense.tv.vpn.action.REFRESH"

        private const val TAG = "GeDefenseTvVpn"
        private const val NOTIFICATION_ID = 7301
        private const val CHANNEL_ID = "gedefense_tv_vpn"
        private const val IPV4_ADDRESS = "10.253.0.2"
        private const val IPV6_ADDRESS = "fd7a:4744::2"
        private const val MTU = 1280
        private const val MAX_PHYSICAL_NETWORKS = 4
        private const val MAX_RETRY_ATTEMPTS = 6
        private const val RETRY_BASE_DELAY_MILLIS = 2_000L
        private const val RETRY_MAX_DELAY_MILLIS = 60_000L

        fun startIntent(context: Context): Intent =
            Intent(context, TvVpnService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, TvVpnService::class.java).setAction(ACTION_STOP)

        fun refreshIntent(context: Context): Intent =
            Intent(context, TvVpnService::class.java).setAction(ACTION_REFRESH)
    }
}
