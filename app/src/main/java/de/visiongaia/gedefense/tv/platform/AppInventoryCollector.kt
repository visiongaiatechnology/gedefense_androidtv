package de.visiongaia.gedefense.tv.platform

import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import de.visiongaia.gedefense.tv.core.model.AppInventory
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.InstalledApp
import de.visiongaia.gedefense.tv.core.model.InventoryDelta
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.TvEvent
import de.visiongaia.gedefense.tv.data.TvInventoryBaseline
import java.security.MessageDigest

/**
 * Reads the apps visible to this TV app through Android package-visibility rules.
 *
 * Honest limits (datasheet section 4/5.2):
 *  - no QUERY_ALL_PACKAGES and no privileged access; on Android 11+ only packages matched by the
 *    manifest `<queries>` (launchable TV/phone apps, https VIEW) plus the app itself are visible, so
 *    the inventory is always PARTIAL and never claims to be a complete device inventory;
 *  - there is no trustworthy denominator for "all installed apps", so coverage reports the observed
 *    count with `total = null`;
 *  - signature digests are public signing metadata, not an integrity or malware proof;
 *  - the label/version/signature read is best effort per package: a malformed package is skipped and
 *    degrades the data quality instead of failing the collector.
 */
class AppInventoryCollector(context: Context) : TvCollector {
    private val appContext = context.applicationContext
    private val packageManager: PackageManager = appContext.packageManager
    private val baseline = TvInventoryBaseline(appContext)

    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "app-inventory",
        category = CollectorCategory.APPS,
        titleKey = "collector.appinventory.title",
        descriptionKey = "collector.appinventory.description",
        restrictedOnSomeDevices = true,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    @Volatile
    var lastInventory: AppInventory? = null
        private set

    @Volatile
    var lastDelta: InventoryDelta = InventoryDelta.NONE
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        return try {
            if (cancel.isCancelled()) throw InterruptedException("app inventory cancelled")
            val packages = try {
                packageManager.getInstalledPackages(packageQueryFlags())
            } catch (_: SecurityException) {
                return CollectorSupport.degraded(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = System.currentTimeMillis(),
                    capability = de.visiongaia.gedefense.tv.core.model.CapabilityState.PERMISSION_REQUIRED,
                    errorKey = MessageRef(CollectorSupport.KEY_COLLECTOR_PERMISSION_REQUIRED),
                )
            } catch (_: Throwable) {
                return CollectorSupport.failed(
                    descriptor = descriptor,
                    startedAtMillis = startedAt,
                    completedAtMillis = System.currentTimeMillis(),
                )
            }

            val byPackage = LinkedHashMap<String, InstalledApp>(minOf(packages.size, MAX_APPS))
            var skipped = 0
            for (packageInfo in packages) {
                if (byPackage.size >= MAX_APPS) break
                if (cancel.isCancelled()) throw InterruptedException("app inventory cancelled")
                val app = try {
                    toInstalledApp(packageInfo)
                } catch (_: Throwable) {
                    null
                }
                if (app == null) {
                    skipped++
                } else if (!byPackage.containsKey(app.packageName)) {
                    byPackage[app.packageName] = app
                }
            }
            val apps = byPackage.values.sortedBy { it.packageName }
            val completedAt = System.currentTimeMillis()
            val launcherCandidates = countLauncherCandidates(apps)
            val inventory = AppInventory(
                apps = apps,
                visibility = DataVisibility.PARTIAL,
                scannedAtMillis = completedAt,
                packageVisibilityRestricted = true,
                declaredQueryPackages = 0,
                launcherCandidates = launcherCandidates,
            )
            lastInventory = inventory
            val delta = baseline.computeDelta(apps, completedAt)
            lastDelta = delta
            lastEvents = listOfNotNull(
                CollectorSupport.event(
                    eventClass = EventClass.TV_APP_INVENTORY,
                    collectorId = descriptor.id,
                    deviceId = environment.deviceId,
                    osApiLevel = environment.platform.sdkInt,
                    eventTimeMillis = completedAt,
                    subject = "visible-app-inventory",
                    dataQuality = if (skipped > 0) DataQuality.PARTIAL else DataQuality.FRESH,
                    attributes = mapOf(
                        "visible_apps" to apps.size.toString(),
                        "launcher_candidates" to launcherCandidates.toString(),
                        "package_visibility_restricted" to "true",
                        "declared_query_packages" to "0",
                        "skipped_packages" to skipped.toString(),
                        "delta_new" to delta.newPackages.size.toString(),
                        "delta_changed" to delta.changedPackages.size.toString(),
                        "delta_removed" to delta.removedPackages.size.toString(),
                        "baseline_available" to delta.baselineAvailable.toString(),
                    ),
                ),
            )
            CollectorSupport.supported(
                descriptor = descriptor,
                startedAtMillis = startedAt,
                completedAtMillis = completedAt,
                visibility = DataVisibility.PARTIAL,
                dataQuality = if (skipped > 0) DataQuality.PARTIAL else DataQuality.FRESH,
                coverage = CollectorCoverage(
                    observed = apps.size,
                    total = null,
                    note = MessageRef(CollectorSupport.KEY_COVERAGE_PACKAGE_VISIBILITY),
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

    private fun packageQueryFlags(): Int {
        val signingFlag = if (Build.VERSION.SDK_INT >= 28) {
            PackageManager.GET_SIGNING_CERTIFICATES
        } else {
            @Suppress("DEPRECATION")
            PackageManager.GET_SIGNATURES
        }
        // GET_PERMISSIONS is deliberately not requested: the TV model does not expose declared
        // permissions, so the app does not collect data it never shows or reports.
        return signingFlag
    }

    private fun toInstalledApp(packageInfo: PackageInfo): InstalledApp? {
        val applicationInfo = packageInfo.applicationInfo ?: return null
        val packageName = packageInfo.packageName
        if (packageName == null || !PACKAGE_NAME_PATTERN.matches(packageName)) return null
        val rawLabel = try {
            applicationInfo.loadLabel(packageManager)?.toString()
        } catch (_: Throwable) {
            null
        }
        val versionName = CollectorSupport.oneLine(packageInfo.versionName, 64).ifBlank { null }
        val versionCode = if (Build.VERSION.SDK_INT >= 28) {
            packageInfo.longVersionCode
        } else {
            @Suppress("DEPRECATION")
            packageInfo.versionCode.toLong()
        }
        val isSystemApp = (applicationInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0
        val installer = installerOf(packageName)
        return InstalledApp(
            packageName = packageName,
            label = CollectorSupport.oneLine(rawLabel, 160).ifBlank { packageName },
            versionName = versionName,
            versionCode = versionCode.coerceAtLeast(0L),
            isSystemApp = isSystemApp,
            installerPackage = installer?.takeIf { PACKAGE_NAME_PATTERN.matches(it) },
            firstInstallTimeMillis = packageInfo.firstInstallTime.coerceAtLeast(0L),
            lastUpdateTimeMillis = packageInfo.lastUpdateTime.coerceAtLeast(0L),
            signatureSha256 = signatureDigests(packageInfo),
            enabled = applicationInfo.enabled,
        )
    }

    private fun installerOf(packageName: String): String? = try {
        if (Build.VERSION.SDK_INT >= 30) {
            packageManager.getInstallSourceInfo(packageName).installingPackageName
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstallerPackageName(packageName)
        }
    } catch (_: Throwable) {
        null
    }

    private fun signatureDigests(packageInfo: PackageInfo): List<String> {
        val certificates: Array<Signature> = try {
            if (Build.VERSION.SDK_INT >= 28) {
                val signingInfo = packageInfo.signingInfo
                when {
                    signingInfo == null -> legacySignatures(packageInfo)
                    signingInfo.hasMultipleSigners() -> signingInfo.apkContentsSigners
                    else -> signingInfo.signingCertificateHistory
                }
            } else {
                legacySignatures(packageInfo)
            }
        } catch (_: Throwable) {
            emptyArray()
        }
        val digests = LinkedHashSet<String>()
        for (certificate in certificates) {
            if (digests.size >= MAX_SIGNERS) break
            val signer = certificate ?: continue
            try {
                digests.add(sha256Hex(signer.toByteArray()))
            } catch (_: Throwable) {
                // A single unreadable certificate must not fail the inventory.
            }
        }
        return digests.sorted()
    }

    @Suppress("DEPRECATION")
    private fun legacySignatures(packageInfo: PackageInfo): Array<Signature> =
        try {
            packageInfo.signatures ?: emptyArray()
        } catch (_: Throwable) {
            emptyArray()
        }

    private fun countLauncherCandidates(apps: List<InstalledApp>): Int {
        val visible = apps.mapTo(HashSet()) { it.packageName }
        val launchers = HashSet<String>()
        for (intent in LAUNCHER_INTENTS) {
            try {
                val resolved = packageManager.queryIntentActivities(intent, 0)
                for (index in resolved.indices) {
                    if (launchers.size >= MAX_APPS) break
                    val packageName = resolved[index].activityInfo?.packageName ?: continue
                    launchers.add(packageName)
                }
            } catch (_: Throwable) {
                // Launcher counting is a hint; a restricted OEM query only reduces the count.
            }
        }
        return launchers.count { it in visible }.coerceIn(0, MAX_APPS)
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val MAX_APPS = 5_000
        private const val MAX_SIGNERS = 16
        private val PACKAGE_NAME_PATTERN = Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+")
        private val LAUNCHER_INTENTS = listOf(
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER),
            Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER),
        )
    }
}
