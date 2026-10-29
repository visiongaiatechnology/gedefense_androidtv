package de.visiongaia.gedefense.tv.platform

import android.content.Context
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build
import de.visiongaia.gedefense.tv.core.model.CancelSignal
import de.visiongaia.gedefense.tv.core.model.CollectorCategory
import de.visiongaia.gedefense.tv.core.model.CollectorCoverage
import de.visiongaia.gedefense.tv.core.model.CollectorDescriptor
import de.visiongaia.gedefense.tv.core.model.CollectorEnvironment
import de.visiongaia.gedefense.tv.core.model.CollectorResult
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.PatchStatus
import de.visiongaia.gedefense.tv.core.model.PlatformIdentity
import de.visiongaia.gedefense.tv.core.model.TvEvent

/**
 * Reads the public Android build identity required by the datasheet (section 3).
 *
 * The collector only reports public build metadata; it never claims an integrity proof. Missing or
 * unreadable values stay "unknown" instead of being replaced by an optimistic default. The
 * environment the scan engine hands over already carries identity and patch assessment (both are
 * built by [readIdentity] / [PatchPolicy] before the engine starts), so this collector is a cheap,
 * deterministic normaliser and event producer and does not need an Android [Context] of its own.
 */
class PlatformCollector(@Suppress("UNUSED_PARAMETER") context: Context) : TvCollector {
    override val descriptor: CollectorDescriptor = CollectorSupport.descriptor(
        id = "platform",
        category = CollectorCategory.PLATFORM,
        titleKey = "collector.platform.title",
        descriptionKey = "collector.platform.description",
        restrictedOnSomeDevices = false,
    )

    @Volatile
    override var lastEvents: List<TvEvent> = emptyList()
        private set

    override fun collect(environment: CollectorEnvironment, cancel: CancelSignal): CollectorResult {
        val startedAt = System.currentTimeMillis()
        if (cancel.isCancelled()) throw InterruptedException("platform collector cancelled")
        val platform = environment.platform
        val patch = environment.patch
        val completedAt = System.currentTimeMillis()

        val patchReadable = patch.status != PatchStatus.UNKNOWN
        val visibility = if (patchReadable) DataVisibility.FULL else DataVisibility.PARTIAL
        val dataQuality = if (patchReadable) DataQuality.FRESH else DataQuality.PARTIAL

        lastEvents = listOfNotNull(
            CollectorSupport.event(
                eventClass = EventClass.TV_DEVICE_STATE,
                collectorId = descriptor.id,
                deviceId = environment.deviceId,
                osApiLevel = platform.sdkInt,
                eventTimeMillis = completedAt,
                subject = platform.displayModel.ifBlank { "android-tv" },
                dataQuality = dataQuality,
                attributes = mapOf(
                    "sdk" to platform.sdkInt.toString(),
                    "release" to platform.androidRelease,
                    "manufacturer" to platform.manufacturer,
                    "model" to platform.model,
                    "device" to platform.device,
                    "fingerprint" to platform.fingerprint,
                    "security_patch" to (platform.securityPatch ?: "unknown"),
                    "patch_status" to patch.status.name,
                    "build_time" to (platform.buildTimeMillis?.toString() ?: "unknown"),
                    "abis" to platform.supportedAbis.joinToString(","),
                    "app_version" to platform.appVersionName,
                    "app_debuggable" to platform.appDebuggable.toString(),
                ),
            ),
        )

        return CollectorSupport.supported(
            descriptor = descriptor,
            startedAtMillis = startedAt,
            completedAtMillis = completedAt,
            visibility = visibility,
            dataQuality = dataQuality,
            coverage = CollectorCoverage(
                observed = if (patchReadable) 7 else 6,
                total = 7,
                note = if (patchReadable) null else CollectorSupport.KEY_COVERAGE_PARTIAL.let {
                    de.visiongaia.gedefense.tv.core.model.MessageRef(it)
                },
            ),
        )
    }

    companion object {
        /** Best-effort identity read used to build the collector environment before the engine run. */
        fun readIdentity(context: Context): PlatformIdentity {
            val packageManager = context.packageManager
            val packageInfo = try {
                packageManager.getPackageInfo(context.packageName, 0)
            } catch (_: PackageManager.NameNotFoundException) {
                null
            } catch (_: RuntimeException) {
                null
            }
            val applicationInfo: ApplicationInfo? = packageInfo?.applicationInfo
            val abis = try {
                Build.SUPPORTED_ABIS
                    ?.filter { it.isNotBlank() }
                    ?.take(8)
                    ?.ifEmpty { listOf("unknown") }
                    ?: listOf("unknown")
            } catch (_: Throwable) {
                listOf("unknown")
            }
            val versionCode = if (Build.VERSION.SDK_INT >= 28) {
                packageInfo?.longVersionCode ?: 0L
            } else {
                @Suppress("DEPRECATION")
                (packageInfo?.versionCode?.toLong() ?: 0L)
            }
            return PlatformIdentity(
                sdkInt = try {
                    Build.VERSION.SDK_INT.coerceAtLeast(1)
                } catch (_: Throwable) {
                    1
                },
                androidRelease = CollectorSupport.oneLine(Build.VERSION.RELEASE, 64).ifBlank { "unknown" },
                manufacturer = CollectorSupport.oneLine(Build.MANUFACTURER, 128),
                model = CollectorSupport.oneLine(Build.MODEL, 128),
                device = CollectorSupport.oneLine(Build.DEVICE, 128),
                fingerprint = CollectorSupport.oneLine(Build.FINGERPRINT, 256),
                securityPatch = try {
                    CollectorSupport.oneLine(Build.VERSION.SECURITY_PATCH, 32).ifBlank { null }
                } catch (_: Throwable) {
                    null
                },
                buildTimeMillis = try {
                    Build.TIME.takeIf { it > 0L }
                } catch (_: Throwable) {
                    null
                },
                supportedAbis = abis,
                appVersionName = CollectorSupport.oneLine(packageInfo?.versionName, 64).ifBlank { "unknown" },
                appVersionCode = versionCode.coerceAtLeast(0L),
                appDebuggable = applicationInfo != null &&
                    (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE) != 0,
            )
        }
    }
}
