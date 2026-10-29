package de.visiongaia.gedefense.tv.core.model

/**
 * Raw, read-only hardening observations gathered by the Android collector.
 *
 * Every value is tri-state: [Observed.readable] == false means the platform did not expose the
 * value (permission, OEM change, API level). The rule engine must treat unreadable values as
 * reduced visibility, never as "disabled/secure".
 */
data class HardeningObservations(
    val collectedAtMillis: Long,
    val adbEnabled: Observed<Boolean>,
    val developerOptionsEnabled: Observed<Boolean>,
    val ownAppCanInstallUnknownApps: Observed<Boolean>,
    val buildTags: List<String>,
    val buildType: String,
    val activeDeviceAdminPackages: List<String>,
    val accessibilityEnabledServices: List<AccessibilityService>,
    val accessibilityKnownSystemPackages: Set<String>,
    val visibleNonStoreInstallers: List<String>,
    val ownInstallerPackage: String?,
) {
    init {
        require(collectedAtMillis > 0L) { "invalid hardening timestamp" }
        require(buildTags.size <= 16) { "too many build tags" }
        require(buildType.length <= 32) { "invalid build type" }
        require(activeDeviceAdminPackages.size <= 64) { "too many device admins" }
        require(accessibilityEnabledServices.size <= 256) { "too many accessibility services" }
        require(visibleNonStoreInstallers.size <= 512) { "too many installer packages" }
        require(accessibilityKnownSystemPackages.size <= 256) { "too many known accessibility packages" }
    }

    /** True when the build itself advertises a non-production signing/build configuration. */
    val testKeysBuild: Boolean
        get() = buildTags.any { it.contains("test-keys", ignoreCase = true) } ||
            buildType.equals("userdebug", ignoreCase = true) ||
            buildType.equals("eng", ignoreCase = true)
}

/** One enabled accessibility service as visible through the public AccessibilityManager APIs. */
data class AccessibilityService(
    val packageName: String,
    val label: String,
    val isSystemPackage: Boolean,
) {
    init {
        require(packageName.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))) {
            "invalid accessibility package: $packageName"
        }
        require(label.length <= 160) { "accessibility label too long" }
    }
}
