package de.visiongaia.gedefense.tv.platform

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanBoundedProcess
import java.net.InetSocketAddress
import java.net.Socket
import de.visiongaia.gedefense.tv.core.model.AccessibilityService
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.HardeningObservations
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.Observed
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.core.rules.DefaultHardeningRules

/**
 * Collects the hardening observations the datasheet requires (section 5.3).
 *
 * Every observation is tri-state via [Observed]: an unreadable platform value is explicitly
 * unreadable and is never reported as "secure/disabled". Rules are evaluated by the pure tv-core
 * [DefaultHardeningRules] engine; this collector only gathers and normalises facts.
 *
 * The collector deliberately does not request or read any additional permission: all values come from
 * public Settings/DevicePolicyManager/AccessibilityManager APIs plus the app's own package metadata.
 */
class HardeningCollector(context: Context) : TvCollector {
    private val appContext = context.applicationContext
    private val packageManager: PackageManager = appContext.packageManager

    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "hardening",
        category = CollectorCategory.HARDENING,
        titleKey = "collector.hardening.title",
        descriptionKey = "collector.hardening.description",
        restrictedOnSomeDevices = true,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        return try {
            if (cancel.isCancelled()) throw InterruptedException("hardening collector cancelled")
            val collectedAt = System.currentTimeMillis()

            val adbEnabled = readGlobalFlag(Settings.Global.ADB_ENABLED)
            val developerOptions = readGlobalFlag(Settings.Global.DEVELOPMENT_SETTINGS_ENABLED)
            val unknownSources = readUnknownSources()
            val buildTags = readBuildTags()
            val buildType = CollectorSupport.oneLine(Build.TYPE, 32)
            val admins = readActiveAdmins()
            val accessibility = readAccessibilityServices()
            val ownInstaller = readOwnInstaller()
            val packageSignals = readVisiblePackageSignals()
            val selinuxEnforcing = readSelinuxEnforcing()
            val adbTcpExposed = readAdbTcpExposed()
            val adbWifiEnabled = readGlobalFlag(SETTING_ADB_WIFI_ENABLED)
            val adbUnauthenticated = readAdbUnauthenticated()
            val networkHardening = readNetworkHardening()

            if (cancel.isCancelled()) throw InterruptedException("hardening collector cancelled")

            val observations = HardeningObservations(
                collectedAtMillis = collectedAt,
                adbEnabled = adbEnabled,
                developerOptionsEnabled = developerOptions,
                ownAppCanInstallUnknownApps = unknownSources,
                buildTags = buildTags,
                buildType = buildType,
                activeDeviceAdminPackages = admins.packages,
                accessibilityEnabledServices = accessibility.services,
                accessibilityKnownSystemPackages = KNOWN_SYSTEM_ACCESSIBILITY_PACKAGES,
                visibleNonStoreInstallers = packageSignals.nonStoreInstallers,
                ownInstallerPackage = ownInstaller.packageName,
                selinuxEnforcing = selinuxEnforcing,
                adbTcpExposed = adbTcpExposed,
                adbWifiEnabled = adbWifiEnabled,
                adbUnauthenticated = adbUnauthenticated,
                httpProxyConfigured = networkHardening.httpProxyConfigured,
                privateDnsActive = networkHardening.privateDnsActive,
                visibleSideloadedApps = packageSignals.sideloadedApps,
                visibleDebuggableApps = packageSignals.debuggableApps,
            )

            val evidence = CollectorSupport.evidence(descriptor.id, collectedAt)
            var evaluationFailed = false
            val findings = try {
                DefaultHardeningRules.evaluate(observations, evidence)
            } catch (_: Throwable) {
                evaluationFailed = true
                emptyList()
            }

            val readableChecks = listOf(
                adbEnabled.readable,
                developerOptions.readable,
                unknownSources.readable,
                true, // build tags/type are always readable
                admins.readable,
                accessibility.readable,
                ownInstaller.readable,
                packageSignals.readable,
                selinuxEnforcing.readable,
                adbTcpExposed.readable,
                adbWifiEnabled.readable,
                adbUnauthenticated.readable,
                networkHardening.httpProxyConfigured.readable,
                networkHardening.privateDnsActive.readable,
            ).count { it }
            val totalChecks = TOTAL_CHECKS
            // The installer enumeration is bounded by package visibility on Android 11+, so even a
            // fully readable device keeps PARTIAL visibility for this collector.
            val packageVisibilityPartial = Build.VERSION.SDK_INT >= 30
            val visibility = if (readableChecks == totalChecks && !packageVisibilityPartial) {
                DataVisibility.FULL
            } else {
                DataVisibility.PARTIAL
            }
            val dataQuality = if (readableChecks == totalChecks && !evaluationFailed) {
                DataQuality.FRESH
            } else {
                DataQuality.PARTIAL
            }
            val completedAt = System.currentTimeMillis()
            CollectorSupport.supported(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = completedAt,
                visibility = visibility,
                dataQuality = dataQuality,
                findings = findings,
                coverage = CollectorCoverage(
                    observed = readableChecks,
                    total = totalChecks,
                    note = if (readableChecks < totalChecks) MessageRef(CollectorSupport.KEY_COVERAGE_PARTIAL) else null,
                ),
                errorKey = if (evaluationFailed) MessageRef(CollectorSupport.KEY_COLLECTOR_PARTIAL_COVERAGE) else null,
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

    private fun readGlobalFlag(setting: String): Observed<Boolean> = try {
        val value = Settings.Global.getInt(appContext.contentResolver, setting, UNSET)
        when (value) {
            0 -> Observed.of(false)
            1 -> Observed.of(true)
            else -> Observed.unreadable()
        }
    } catch (_: Throwable) {
        Observed.unreadable()
    }

    @Suppress("DEPRECATION")
    private fun readUnknownSources(): Observed<Boolean> = try {
        if (Build.VERSION.SDK_INT >= 26) {
            Observed.of(packageManager.canRequestPackageInstalls())
        } else {
            Observed.unreadable()
        }
    } catch (_: Throwable) {
        Observed.unreadable()
    }

    private fun readBuildTags(): List<String> = try {
        Build.TAGS
            ?.split(',')
            ?.map { CollectorSupport.oneLine(it, 64) }
            ?.filter { it.isNotEmpty() }
            ?.distinct()
            ?.take(16)
            ?: emptyList()
    } catch (_: Throwable) {
        emptyList()
    }

    private data class AdminRead(val packages: List<String>, val readable: Boolean)

    @Suppress("DEPRECATION")
    private fun readActiveAdmins(): AdminRead = try {
        val devicePolicy = appContext.getSystemService(Context.DEVICE_POLICY_SERVICE) as? DevicePolicyManager
        if (devicePolicy == null) {
            AdminRead(emptyList(), readable = false)
        } else {
            val admins = devicePolicy.activeAdmins
            val packages = admins.orEmpty()
                .mapNotNull { component -> component?.packageName }
                .filter { packageName -> PACKAGE_NAME_PATTERN.matches(packageName) }
                .distinct()
                .take(64)
            AdminRead(packages, readable = true)
        }
    } catch (_: Throwable) {
        AdminRead(emptyList(), readable = false)
    }

    private data class AccessibilityRead(val services: List<AccessibilityService>, val readable: Boolean)

    private fun readAccessibilityServices(): AccessibilityRead = try {
        val manager = appContext.getSystemService(Context.ACCESSIBILITY_SERVICE) as? AccessibilityManager
        if (manager == null) {
            AccessibilityRead(emptyList(), readable = false)
        } else {
            val enabled = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK)
            val services = ArrayList<AccessibilityService>(minOf(enabled.size, MAX_ACCESSIBILITY_SERVICES))
            for (info in enabled) {
                if (services.size >= MAX_ACCESSIBILITY_SERVICES) break
                val resolveInfo = info?.resolveInfo ?: continue
                val serviceInfo = resolveInfo.serviceInfo ?: continue
                val packageName = serviceInfo.packageName ?: continue
                if (!PACKAGE_NAME_PATTERN.matches(packageName)) continue
                if (services.any { it.packageName == packageName }) continue
                val rawLabel = try {
                    resolveInfo.loadLabel(packageManager).toString()
                } catch (_: Throwable) {
                    null
                }
                val isSystemPackage = try {
                    val flags = serviceInfo.applicationInfo?.flags ?: 0
                    (flags and ApplicationInfo.FLAG_SYSTEM) != 0
                } catch (_: Throwable) {
                    false
                }
                val service = try {
                    AccessibilityService(
                        packageName = packageName,
                        label = CollectorSupport.oneLine(rawLabel, 160).ifBlank { packageName },
                        isSystemPackage = isSystemPackage,
                    )
                } catch (_: IllegalArgumentException) {
                    null
                }
                if (service != null) services.add(service)
            }
            AccessibilityRead(services, readable = true)
        }
    } catch (_: Throwable) {
        AccessibilityRead(emptyList(), readable = false)
    }

    private data class InstallerRead(val packageName: String?, val readable: Boolean)

    private fun readOwnInstaller(): InstallerRead = try {
        val installer = if (Build.VERSION.SDK_INT >= 30) {
            packageManager.getInstallSourceInfo(appContext.packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(appContext.packageName)
        }
        InstallerRead(installer?.takeIf { PACKAGE_NAME_PATTERN.matches(it) }, readable = true)
    } catch (_: Throwable) {
        InstallerRead(null, readable = false)
    }

    private data class PackageSignalsRead(
        val nonStoreInstallers: List<String>,
        val sideloadedApps: List<String>,
        val debuggableApps: List<String>,
        val readable: Boolean,
    )

    private fun readVisiblePackageSignals(): PackageSignalsRead = try {
        val installers = LinkedHashSet<String>()
        val sideloaded = LinkedHashSet<String>()
        val debuggable = LinkedHashSet<String>()
        val packages = packageManager.getInstalledPackages(0)
        val bound = minOf(packages.size, MAX_INSTALLER_SCAN)
        for (index in 0 until bound) {
            val packageInfo = packages[index]
            val packageName = packageInfo?.packageName ?: continue
            if (packageName == appContext.packageName) continue
            if (!PACKAGE_NAME_PATTERN.matches(packageName)) continue
            val appInfo = packageInfo.applicationInfo
            val isSystem = appInfo != null && (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
            val isDebuggable = appInfo != null && (appInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0
            if (!isSystem && isDebuggable && debuggable.size < 256) {
                debuggable.add(packageName)
            }
            val installer = try {
                if (Build.VERSION.SDK_INT >= 30) {
                    packageManager.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getInstallerPackageName(packageName)
                }
            } catch (_: Throwable) {
                null
            }
            if (!isSystem && (installer == null || installer !in InstalledApp.KNOWN_STORES)) {
                if (sideloaded.size < 512) sideloaded.add(packageName)
            }
            if (installer != null && installer !in InstalledApp.KNOWN_STORES &&
                installer != appContext.packageName && PACKAGE_NAME_PATTERN.matches(installer) &&
                installers.size < 512
            ) {
                installers.add(installer)
            }
        }
        PackageSignalsRead(
            nonStoreInstallers = installers.toList().sorted(),
            sideloadedApps = sideloaded.toList().sorted(),
            debuggableApps = debuggable.toList().sorted(),
            readable = true,
        )
    } catch (_: Throwable) {
        PackageSignalsRead(emptyList(), emptyList(), emptyList(), readable = false)
    }

    private fun readSelinuxEnforcing(): Observed<Boolean> = try {
        val outcome = TitanBoundedProcess.run(
            argv = listOf(GETENFORCE_PROGRAM),
            workingDirectory = null,
            timeoutMillis = LOCAL_PROBE_TIMEOUT_MILLIS,
            maxBytes = LOCAL_PROBE_CAP_BYTES,
        )
        val value = if (outcome.started && !outcome.timedOut && outcome.exitCode == 0) {
            outcome.output.trim()
        } else {
            ""
        }
        when {
            value.isEmpty() -> Observed.unreadable()
            value.equals(SELINUX_ENFORCING, ignoreCase = true) -> Observed.of(true)
            else -> Observed.of(false)
        }
    } catch (_: Throwable) {
        Observed.unreadable()
    }

    private fun readAdbTcpExposed(): Observed<Boolean> {
        val propRaw = readProp(PROPERTY_ADB_TCP_PORT)
        val propPort = propRaw?.trim()?.toIntOrNull()
        if (propPort != null && propPort > 0) return Observed.of(true)
        if (probeLocalhostTcp(ADB_TCP_PORT)) return Observed.of(true)
        return if (propRaw != null) Observed.of(false) else Observed.unreadable()
    }

    private fun readAdbUnauthenticated(): Observed<Boolean> = when (readProp(PROPERTY_ADB_SECURE)?.trim()) {
        "0" -> Observed.of(true)
        "1" -> Observed.of(false)
        else -> Observed.unreadable()
    }

    private fun readProp(name: String): String? = try {
        val outcome = TitanBoundedProcess.run(
            argv = listOf(GETPROP_PROGRAM, name),
            workingDirectory = null,
            timeoutMillis = LOCAL_PROBE_TIMEOUT_MILLIS,
            maxBytes = LOCAL_PROBE_CAP_BYTES,
        )
        if (outcome.started && !outcome.timedOut && !outcome.truncated && outcome.exitCode == 0) {
            outcome.output
        } else {
            null
        }
    } catch (_: Throwable) {
        null
    }

    private fun probeLocalhostTcp(port: Int): Boolean = try {
        Socket().use { socket ->
            socket.connect(InetSocketAddress("127.0.0.1", port), LOOPBACK_PROBE_TIMEOUT_MS)
            true
        }
    } catch (_: Throwable) {
        false
    }

    private data class NetworkHardeningRead(
        val httpProxyConfigured: Observed<Boolean>,
        val privateDnsActive: Observed<Boolean>,
    )

    private fun readNetworkHardening(): NetworkHardeningRead = try {
        val cm = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (cm == null) {
            NetworkHardeningRead(Observed.unreadable(), Observed.unreadable())
        } else {
            val link = activePhysicalLinkProperties(cm)
            if (link == null) {
                NetworkHardeningRead(Observed.unreadable(), Observed.unreadable())
            } else {
                val hasProxy = link.httpProxy != null
                val privateDns = if (Build.VERSION.SDK_INT >= 28) {
                    Observed.of(link.isPrivateDnsActive)
                } else {
                    Observed.unreadable()
                }
                NetworkHardeningRead(Observed.of(hasProxy), privateDns)
            }
        }
    } catch (_: Throwable) {
        NetworkHardeningRead(Observed.unreadable(), Observed.unreadable())
    }

    @Suppress("DEPRECATION")
    private fun activePhysicalLinkProperties(cm: ConnectivityManager): LinkProperties? {
        val networks = runCatching { cm.allNetworks }.getOrNull().orEmpty()
        for (network in networks) {
            val caps = runCatching { cm.getNetworkCapabilities(network) }.getOrNull() ?: continue
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) continue
            if (!caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue
            val props = runCatching { cm.getLinkProperties(network) }.getOrNull()
            if (props != null) return props
        }
        return cm.activeNetwork?.let { runCatching { cm.getLinkProperties(it) }.getOrNull() }
    }

    companion object {
        private const val UNSET = -1
        private const val TOTAL_CHECKS = 14
        private const val MAX_ACCESSIBILITY_SERVICES = 256
        private const val MAX_INSTALLER_SCAN = 1_500
        private const val GETENFORCE_PROGRAM = "getenforce"
        private const val GETPROP_PROGRAM = "getprop"
        private const val SELINUX_ENFORCING = "Enforcing"
        private const val PROPERTY_ADB_TCP_PORT = "service.adb.tcp.port"
        private const val PROPERTY_ADB_SECURE = "ro.adb.secure"
        private const val SETTING_ADB_WIFI_ENABLED = "adb_wifi_enabled"
        private const val ADB_TCP_PORT = 5_555
        private const val LOOPBACK_PROBE_TIMEOUT_MS = 150
        private const val LOCAL_PROBE_TIMEOUT_MILLIS = 1_500L
        private const val LOCAL_PROBE_CAP_BYTES = 2 * 1024
        private val PACKAGE_NAME_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")

        /** Conservative allowlist of accessibility packages that ship with Android TV / Google TV. */
        val KNOWN_SYSTEM_ACCESSIBILITY_PACKAGES: Set<String> = setOf(
            "com.google.android.marvin.talkback",
            "com.android.talkback",
            "com.google.android.accessibility.switchaccess",
            "com.google.android.apps.accessibility.voiceaccess",
            "com.google.android.accessibility.selecttospeak",
            "com.android.systemui",
            "com.android.tv.settings",
            "com.google.android.tv.settings",
            "com.android.settings",
            "com.google.android.gms",
        )
    }
}
