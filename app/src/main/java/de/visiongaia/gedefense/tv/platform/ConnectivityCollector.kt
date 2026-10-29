package de.visiongaia.gedefense.tv.platform

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.TvEvent
import java.net.Inet4Address
import java.net.Inet6Address

/** Honest, read-only snapshot of the active network link (no flow, socket or port data). */
data class ConnectivitySnapshot(
    val active: Boolean,
    val transport: String,
    val validated: Boolean?,
    val internetCapable: Boolean?,
    val metered: Boolean?,
    val linkDownKbps: Int?,
    val linkUpKbps: Int?,
    val dnsServers: Int?,
    val linkAddressCount: Int?,
    val hasIpv4: Boolean?,
    val hasIpv6: Boolean?,
    val interfaceName: String?,
)

/**
 * Reads the active network state and link metadata through public ConnectivityManager APIs.
 *
 * Scope limit from the datasheet (section 7): this is NOT a system-wide flow monitor. The app reports
 * the network/link snapshot only; it never claims packet rates, listening ports or per-process flows,
 * because a regular TV app cannot observe them.
 */
class ConnectivityCollector(context: Context) : TvCollector {
    private val appContext = context.applicationContext

    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "connectivity",
        category = CollectorCategory.CONNECTIVITY,
        titleKey = "collector.connectivity.title",
        descriptionKey = "collector.connectivity.description",
        restrictedOnSomeDevices = false,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    @Volatile
    var lastSnapshot: ConnectivitySnapshot? = null
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        return try {
            if (cancel.isCancelled()) throw InterruptedException("connectivity collector cancelled")
            if (!CollectorSupport.isPermissionGranted(appContext, android.Manifest.permission.ACCESS_NETWORK_STATE)) {
                return CollectorSupport.degraded(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = System.currentTimeMillis(),
                    capability = de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED,
                    errorKey = MessageRef(CollectorSupport.KEY_COLLECTOR_PERMISSION_REQUIRED),
                )
            }
            val manager = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
                ?: return CollectorSupport.degraded(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = System.currentTimeMillis(),
                    capability = de.visiongaia.gedefense.tv.core.model.CapabilityState.UNSUPPORTED,
                    errorKey = MessageRef(CollectorSupport.KEY_COLLECTOR_UNSUPPORTED),
                )

            val network = try {
                manager.activeNetwork
            } catch (_: SecurityException) {
                return CollectorSupport.degraded(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = System.currentTimeMillis(),
                    capability = de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED,
                    errorKey = MessageRef(CollectorSupport.KEY_COLLECTOR_PERMISSION_REQUIRED),
                )
            }
            if (network == null) {
                val completedAt = System.currentTimeMillis()
                val snapshot = ConnectivitySnapshot(
                    active = false,
                    transport = "none",
                    validated = null,
                    internetCapable = null,
                    metered = null,
                    linkDownKbps = null,
                    linkUpKbps = null,
                    dnsServers = null,
                    linkAddressCount = null,
                    hasIpv4 = null,
                    hasIpv6 = null,
                    interfaceName = null,
                )
                lastSnapshot = snapshot
                lastEvents = listOfNotNull(
                    CollectorSupport.event(
                        eventClass = EventClass.TV_CONNECTIVITY_STATE,
                        collectorId = descriptor.id,
                        deviceId = environment.deviceId,
                        osApiLevel = environment.platform.sdkInt,
                        eventTimeMillis = completedAt,
                        subject = "active-network",
                        dataQuality = DataQuality.FRESH,
                        attributes = mapOf("network" to "none"),
                    ),
                )
                return CollectorSupport.supported(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = completedAt,
                    visibility = DataVisibility.FULL,
                    dataQuality = DataQuality.FRESH,
                    coverage = CollectorCoverage(observed = 1, total = 1),
                )
            }

            val capabilities = try {
                manager.getNetworkCapabilities(network)
            } catch (_: Throwable) {
                null
            }
            val linkProperties = try {
                manager.getLinkProperties(network)
            } catch (_: Throwable) {
                null
            }
            val snapshot = snapshotFrom(capabilities, linkProperties)
            lastSnapshot = snapshot
            val completedAt = System.currentTimeMillis()
            lastEvents = listOfNotNull(
                CollectorSupport.event(
                    eventClass = EventClass.TV_CONNECTIVITY_STATE,
                    collectorId = descriptor.id,
                    deviceId = environment.deviceId,
                    osApiLevel = environment.platform.sdkInt,
                    eventTimeMillis = completedAt,
                    subject = "active-network",
                    dataQuality = if (capabilities != null && linkProperties != null) DataQuality.FRESH else DataQuality.PARTIAL,
                    attributes = mapOf(
                        "network_type" to snapshot.transport,
                        "validated" to snapshot.validated.toString(),
                        "internet" to snapshot.internetCapable.toString(),
                        "metered" to snapshot.metered.toString(),
                        "link_down_kbps" to (snapshot.linkDownKbps?.toString() ?: "unknown"),
                        "link_up_kbps" to (snapshot.linkUpKbps?.toString() ?: "unknown"),
                        "dns_servers" to (snapshot.dnsServers?.toString() ?: "unknown"),
                        "link_addresses" to (snapshot.linkAddressCount?.toString() ?: "unknown"),
                        "has_ipv4" to snapshot.hasIpv4.toString(),
                        "has_ipv6" to snapshot.hasIpv6.toString(),
                        "interface" to (snapshot.interfaceName ?: "unknown"),
                    ),
                ),
            )
            val complete = capabilities != null && linkProperties != null
            CollectorSupport.supported(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = completedAt,
                visibility = if (complete) DataVisibility.FULL else DataVisibility.PARTIAL,
                dataQuality = if (complete) DataQuality.FRESH else DataQuality.PARTIAL,
                coverage = CollectorCoverage(
                    observed = (if (capabilities != null) 1 else 0) + (if (linkProperties != null) 1 else 0),
                    total = 2,
                ),
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

    private fun snapshotFrom(capabilities: NetworkCapabilities?, linkProperties: LinkProperties?): ConnectivitySnapshot {
        val transport = when {
            capabilities == null -> "unknown"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
            else -> "other"
        }
        val addresses = linkProperties?.linkAddresses
        val hasIpv4 = addresses?.any { it.address is Inet4Address }
        val hasIpv6 = addresses?.any { it.address is Inet6Address }
        return ConnectivitySnapshot(
            active = true,
            transport = transport,
            validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            internetCapable = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
            metered = capabilities?.let {
                !it.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
            },
            linkDownKbps = capabilities?.linkDownstreamBandwidthKbps,
            linkUpKbps = capabilities?.linkUpstreamBandwidthKbps,
            dnsServers = linkProperties?.dnsServers?.size,
            linkAddressCount = addresses?.size,
            hasIpv4 = hasIpv4,
            hasIpv6 = hasIpv6,
            interfaceName = CollectorSupport.oneLine(linkProperties?.interfaceName, 64).ifBlank { null },
        )
    }
}
