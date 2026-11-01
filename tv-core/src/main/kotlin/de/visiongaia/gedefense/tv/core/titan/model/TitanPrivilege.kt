package de.visiongaia.gedefense.tv.core.titan.model

import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef

/**
 * Titan privilege level of the running process.
 *
 * The level is never claimed from a filename or a single probe: it is the result of the passive
 * [TitanPrivilegeSnapshot] plus an explicit, user-consented confirmation of a working privileged
 * shell. A level above [STANDARD] therefore always means "a command channel was confirmed", never
 * "a su binary probably exists".
 */
enum class TitanPrivilegeLevel {
    /** Level 1: ordinary, unprivileged TV app. All Titan protections report explicitly unavailable. */
    STANDARD,

    /** Level 2 (concept): Shizuku/ADB bridge. Detection exists; command execution is an Alpha gap. */
    SHIZUKU,

    /** Level 3: user-consented root shell channel was confirmed. */
    ROOT,
}

/**
 * Quality of the detected root/privilege channel.
 *
 * [DIRTY] is a security finding of its own: an `su` binary exists but no known root manager owns the
 * policy, which usually means every app on the device can use it without a prompt (typical for
 * pre-owned/China TV boxes). It is reported, never used as an excuse to raise the level.
 */
enum class TitanRootKind { NONE, MANAGED, DIRTY, UNKNOWN }

/**
 * A capability that Titan can provide only when the confirmed privilege level allows it.
 *
 * Capabilities are the single source of truth for UI, report and evidence: a disabled capability is
 * shown as unavailable, never as "clean" or "protected".
 */
enum class TitanCapability(val id: String) {
    SOCKET_PROVENANCE("socket-provenance"),
    DEEP_INVENTORY_FIM("deep-inventory-fim"),
    APP_FREEZE("app-freeze"),
    NETWORK_QUARANTINE("network-quarantine"),
    ADB_LOCKDOWN("adb-lockdown"),
    PROCESS_KILL("process-kill"),
    QUARANTINE_VAULT("quarantine-vault"),
}

/** Build and kernel hardening facts that are readable without any privilege. */
data class TitanBuildIntegrity(
    /** `Build.TAGS` contains `test-keys`; unsigned/dev image rather than a production build. */
    val testKeys: Boolean = false,
    /** `ro.debuggable == 1`; null when the property could not be read. */
    val debuggableBuild: Boolean? = null,
    /** SELinux is enforcing; null when `getenforce` was unreadable. */
    val selinuxEnforcing: Boolean? = null,
    /** ADB-over-TCP is configured (port 5555 or a custom property); null when unreadable. */
    val adbTcpExposed: Boolean? = null,
    /** Raw `getenforce` output (already shortened); null when unreadable. Never user input. */
    val selinuxRaw: String? = null,
) {
    init {
        require(selinuxRaw == null || selinuxRaw.length <= 32) { "selinux raw state too long" }
    }
}

/**
 * Passive privilege evidence gathered from the device.
 *
 * This snapshot is deliberately pure data: detection never escalates anything, never prompts and
 * never runs a privileged command. The explicit activation flow (user pressed "Titan aktivieren")
 * confirms [rootShellConfirmed]; only then can the level rise above [TitanPrivilegeLevel.STANDARD].
 */
data class TitanPrivilegeSnapshot(
    val level: TitanPrivilegeLevel = TitanPrivilegeLevel.STANDARD,
    val rootKind: TitanRootKind = TitanRootKind.NONE,
    /** Existing `su`-binary candidates (absolute paths, bounded list). */
    val suPaths: List<String> = emptyList(),
    /** Root manager install markers that were found (for example "magisk", "kernelsu", "apatch"). */
    val rootManagers: List<String> = emptyList(),
    /** True only after an explicit, user-consented `su -c id` probe returned root. */
    val rootShellConfirmed: Boolean = false,
    val shizukuInstalled: Boolean = false,
    /** True only when a Shizuku binder bridge was actually reachable. */
    val shizukuBridgeAvailable: Boolean = false,
    val build: TitanBuildIntegrity = TitanBuildIntegrity(),
    val checkedAtMillis: Long,
    /** Stable catalog keys for user-facing notes (see TitanTextKeys). */
    val notes: List<MessageRef> = emptyList(),
) {
    init {
        require(checkedAtMillis > 0L) { "invalid privilege snapshot timestamp" }
        require(suPaths.size <= MAX_PATHS) { "too many su paths" }
        require(suPaths.all { it.length in 1..256 && it.startsWith("/") }) { "invalid su path" }
        require(rootManagers.size <= MAX_MANAGERS) { "too many root managers" }
        require(rootManagers.all { it.matches(MANAGER_PATTERN) }) { "invalid root manager id" }
        require(notes.size <= MAX_NOTES) { "too many privilege notes" }
        require(level != TitanPrivilegeLevel.ROOT || rootShellConfirmed) {
            "root level requires a confirmed root shell"
        }
        require(level != TitanPrivilegeLevel.SHIZUKU || shizukuBridgeAvailable) {
            "shizuku level requires a reachable bridge"
        }
        require(!rootShellConfirmed || level == TitanPrivilegeLevel.ROOT || level == TitanPrivilegeLevel.SHIZUKU) {
            "confirmed root shell must map to an elevated level"
        }
    }

    /** True when the device exposes a su binary without a root manager controlling it. */
    val dirtyRootSuspected: Boolean
        get() = suPaths.isNotEmpty() && rootManagers.isEmpty()

    /** Honest visibility of the areas Titan can inspect at this level. */
    fun visibility(): DataVisibility = when (level) {
        TitanPrivilegeLevel.STANDARD -> DataVisibility.PARTIAL
        TitanPrivilegeLevel.SHIZUKU -> DataVisibility.PARTIAL
        TitanPrivilegeLevel.ROOT -> DataVisibility.FULL
    }

    companion object {
        const val MAX_PATHS = 16
        const val MAX_MANAGERS = 16
        const val MAX_NOTES = 12
        private val MANAGER_PATTERN = Regex("[a-z][a-z0-9-]{1,31}")

        /** Initial, honest state before the first passive detection ran. */
        fun unchecked(nowMillis: Long): TitanPrivilegeSnapshot = TitanPrivilegeSnapshot(
            level = TitanPrivilegeLevel.STANDARD,
            rootKind = TitanRootKind.UNKNOWN,
            checkedAtMillis = nowMillis.coerceAtLeast(1L),
        )
    }
}

/** Stable MessageRef keys used by Titan domain notes (mapped to localized catalog strings). */
object TitanTextKeys {
    const val NOTE_ROOT_DETECTED = "titan.note.rootdetected"
    const val NOTE_DIRTY_ROOT = "titan.note.dirtyroot"
    const val NOTE_SELINUX_PERMISSIVE = "titan.note.selinuxpermissive"
    const val NOTE_TEST_KEYS = "titan.note.testkeys"
    const val NOTE_ADB_EXPOSED = "titan.note.adbexposed"
    const val NOTE_SHIZUKU_DETECTED = "titan.note.shizukudetected"
    const val NOTE_SHIZUKU_BRIDGE_MISSING = "titan.note.shizukubridgemissing"
    const val NOTE_ROOT_SHELL_DENIED = "titan.note.rootshelldenied"
    const val NOTE_STANDARD_ONLY = "titan.note.standardonly"
    const val NOTE_SOCKET_LIMITED = "titan.note.socketlimited"
    const val NOTE_FIM_UNREADABLE = "titan.note.fimunreadable"
    const val NOTE_FIM_BASELINE = "titan.note.fimbaseline"
    const val NOTE_SOCKET_TRUNCATED = "titan.note.sockettruncated"
    const val NOTE_WITNESS_UNPAIRED = "titan.note.witnessunpaired"
    const val NOTE_ACTION_FAILED = "titan.note.actionfailed"

    // Activation and lifecycle outcomes shown by the UI as toast/status text.
    const val KEY_ACTIVATE_OK = "titan.activate.ok"
    const val KEY_ACTIVATE_DENIED = "titan.activate.denied"
    const val KEY_ACTIVATE_NO_CHANNEL = "titan.activate.nochannel"
    const val KEY_ACTIVATE_BRIDGE_UNAVAILABLE = "titan.activate.bridgeunavailable"
    const val KEY_SCAN_FAILED = "titan.scan.failed"
    const val KEY_SCAN_COMPLETED = "titan.scan.completed"
    const val KEY_SCAN_PARTIAL = "titan.scan.partial"
    const val KEY_ACTION_OK = "titan.action.ok"
    const val KEY_ACTION_FAILED = "titan.action.failed"
    const val KEY_WITNESS_OK = "titan.witness.ok"
    const val KEY_WITNESS_UNAVAILABLE = "titan.witness.unavailable"
}
