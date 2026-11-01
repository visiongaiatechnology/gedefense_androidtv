package de.visiongaia.gedefense.tv.core.titan

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot

/**
 * Capability matrix of the three-level privilege model.
 *
 * Two distinct notions are kept apart on purpose:
 *  - [theoreticalCapabilities] answers "what does the concept grant at this level?";
 *  - [effectiveCapabilities] answers "what did this device actually confirm?".
 *
 * The UI and the report must only ever consume the effective set. This is the central Zero-Snake-Oil
 * guard: a detected `su` file does not unlock a capability, only a confirmed command channel does.
 */
object TitanCapabilityMatrix {

    /** Capabilities the concept grants at each level (independent of device reality). */
    fun theoreticalCapabilities(level: TitanPrivilegeLevel): Set<TitanCapability> = when (level) {
        TitanPrivilegeLevel.STANDARD -> emptySet()
        TitanPrivilegeLevel.SHIZUKU -> setOf(
            TitanCapability.SOCKET_PROVENANCE,
            TitanCapability.APP_FREEZE,
        )
        TitanPrivilegeLevel.ROOT -> TitanCapability.values().toSet()
    }

    /** Visibility the concept grants at each level (independent of device reality). */
    fun theoreticalVisibility(level: TitanPrivilegeLevel): DataVisibility = when (level) {
        TitanPrivilegeLevel.STANDARD -> DataVisibility.PARTIAL
        TitanPrivilegeLevel.SHIZUKU -> DataVisibility.PARTIAL
        TitanPrivilegeLevel.ROOT -> DataVisibility.FULL
    }

    /**
     * Capabilities that are actually usable on this device right now.
     *
     * Elevation is only accepted when the corresponding command channel was confirmed:
     *  - ROOT requires [TitanPrivilegeSnapshot.rootShellConfirmed];
     *  - SHIZUKU requires [TitanPrivilegeSnapshot.shizukuBridgeAvailable].
     */
    fun effectiveCapabilities(privilege: TitanPrivilegeSnapshot?): Set<TitanCapability> {
        if (privilege == null) return emptySet()
        val confirmed = when (privilege.level) {
            TitanPrivilegeLevel.STANDARD -> false
            TitanPrivilegeLevel.SHIZUKU -> privilege.shizukuBridgeAvailable
            TitanPrivilegeLevel.ROOT -> privilege.rootShellConfirmed
        }
        return if (confirmed) theoreticalCapabilities(privilege.level) else emptySet()
    }

    /** Effective visibility: FULL only with a confirmed root channel, otherwise PARTIAL. */
    fun effectiveVisibility(privilege: TitanPrivilegeSnapshot?): DataVisibility {
        if (privilege == null) return DataVisibility.PARTIAL
        return if (effectiveCapabilities(privilege).isNotEmpty()) {
            theoreticalVisibility(privilege.level)
        } else {
            DataVisibility.PARTIAL
        }
    }
}
