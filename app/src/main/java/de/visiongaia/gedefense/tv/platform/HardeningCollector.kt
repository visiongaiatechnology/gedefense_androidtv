package de.visiongaia.gedefense.tv.platform

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.admin.DevicePolicyManager
import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import android.provider.Settings
import android.view.accessibility.AccessibilityManager
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
            val nonStoreInstallers = readVisibleNonStoreInstallers()

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
                visibleNonStoreInstallers = nonStoreInstallers.packages,
                ownInstallerPackage = ownInstaller.packageName,
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
                nonStoreInstallers.readable,
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

    private data class InstallersRead(val packages: List<String>, val readable: Boolean)

    private fun readVisibleNonStoreInstallers(): InstallersRead = try {
        val installers = LinkedHashSet<String>()
        val packages = packageManager.getInstalledPackages(0)
        val bound = minOf(packages.size, MAX_INSTALLER_SCAN)
        for (index in 0 until bound) {
            if (installers.size >= 512) break
            val packageInfo = packages[index]
            val packageName = packageInfo?.packageName ?: continue
            if (packageName == appContext.packageName) continue
            val installer = try {
                if (Build.VERSION.SDK_INT >= 30) {
                    packageManager.getInstallSourceInfo(packageName).installingPackageName
                } else {
                    @Suppress("DEPRECATION")
                    packageManager.getInstallerPackageName(packageName)
                }
            } catch (_: Throwable) {
                null
            } ?: continue
            if (installer in InstalledApp.KNOWN_STORES) continue
            if (installer == appContext.packageName) continue
            if (!PACKAGE_NAME_PATTERN.matches(installer)) continue
            installers.add(installer)
        }
        InstallersRead(installers.toList().sorted(), readable = true)
    } catch (_: Throwable) {
        InstallersRead(emptyList(), readable = false)
    }

    companion object {
        private const val UNSET = -1
        private const val TOTAL_CHECKS = 8
        private const val MAX_ACCESSIBILITY_SERVICES = 256
        private const val MAX_INSTALLER_SCAN = 1_500
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
