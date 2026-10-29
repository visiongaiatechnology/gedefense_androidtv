package de.visiongaia.gedefense.tv.core.model

/**
 * One application visible to the TV app through Android package visibility rules.
 *
 * Visibility is bounded by the platform: on Android 11+ the app only sees packages matched by its
 * `<queries>` declarations (plus itself and callers). [AppInventory.packageVisibilityRestricted]
 * records that this bound applies; the UI must never claim a complete device inventory.
 */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val isSystemApp: Boolean,
    val installerPackage: String?,
    val firstInstallTimeMillis: Long,
    val lastUpdateTimeMillis: Long,
    val signatureSha256: List<String>,
    val enabled: Boolean,
) {
    init {
        require(packageName.matches(Regex("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+"))) {
            "invalid package name: $packageName"
        }
        require(label.length <= 160) { "app label too long" }
        require(versionCode >= 0L) { "invalid version code" }
        require(signatureSha256.size <= 16) { "too many signers" }
        require(signatureSha256.all { it.matches(Regex("[0-9a-f]{64}")) }) { "invalid signature digest" }
        require(firstInstallTimeMillis >= 0L && lastUpdateTimeMillis >= 0L) { "invalid install timestamp" }
    }

    /** Launcher/system/known-store heuristic used for review prioritisation only. */
    val installerIsKnownStore: Boolean
        get() = installerPackage == null ||
            installerPackage in KNOWN_STORES ||
            isSystemApp

    companion object {
        /**
         * Conservative allowlist of package-manager installers considered expected on Android TV.
         * This is a review heuristic, not a trust proof: any package can falsely claim no installer.
         */
        val KNOWN_STORES: Set<String> = setOf(
            "com.android.vending",
            "com.google.android.packageinstaller",
            "com.android.packageinstaller",
            "com.google.android.gms",
            "com.android.tv.settings",
        )
    }
}

/** Bounded, honest app inventory snapshot. */
data class AppInventory(
    val apps: List<InstalledApp>,
    val visibility: DataVisibility,
    val scannedAtMillis: Long,
    val packageVisibilityRestricted: Boolean,
    val declaredQueryPackages: Int,
    val launcherCandidates: Int,
) {
    init {
        require(apps.size <= 20_000) { "inventory too large" }
        require(declaredQueryPackages in 0..512) { "invalid query package count" }
        require(launcherCandidates in 0..20_000) { "invalid launcher candidate count" }
        require(apps.map { it.packageName }.toSet().size == apps.size) { "duplicate package in inventory" }
    }

    val byPackage: Map<String, InstalledApp> get() = apps.associateBy { it.packageName }
}

/** Difference between the current inventory and the last accepted baseline. */
data class InventoryDelta(
    val newPackages: List<String>,
    val changedPackages: List<String>,
    val removedPackages: List<String>,
    val baselineAvailable: Boolean,
    val baselineAtMillis: Long?,
) {
    init {
        require(newPackages.size + changedPackages.size + removedPackages.size <= 40_000) { "delta too large" }
        require(!baselineAvailable || baselineAtMillis != null) { "baseline timestamp required" }
    }

    val hasChanges: Boolean get() = newPackages.isNotEmpty() || changedPackages.isNotEmpty() || removedPackages.isNotEmpty()

    companion object {
        val NONE = InventoryDelta(
            newPackages = emptyList(),
            changedPackages = emptyList(),
            removedPackages = emptyList(),
            baselineAvailable = false,
            baselineAtMillis = null,
        )
    }
}
