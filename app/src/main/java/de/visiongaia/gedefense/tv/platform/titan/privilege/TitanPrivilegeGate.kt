package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.Context
import android.os.Build
import android.util.Log
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.TitanBuildIntegrity
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanRootKind
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys
import de.visiongaia.gedefense.tv.vpn.BoundedAndroidCall
import de.visiongaia.gedefense.tv.vpn.PlatformCallUnavailableException
import java.io.File

/**
 * Passive privilege detection and the explicit, user-consented root confirmation of Titan.
 *
 * Honesty rules that are enforced by construction:
 *  - [passiveSnapshot] never raises the level above [TitanPrivilegeLevel.STANDARD], never prompts
 *    for root and never executes a privileged command. It only reads file existence, guarded
 *    `PackageManager` queries and three bounded, non-privileged local probes (`getenforce`,
 *    `getprop ro.debuggable`, `getprop service.adb.tcp.port`).
 *  - A detected `su` file is evidence, not a grant: without a root manager it is reported as
 *    [TitanRootKind.DIRTY] and every elevated capability stays unavailable.
 *  - [confirmRoot] is the only method that runs the root-identity probe, and it is only called from
 *    the explicit `activate()` user flow. It never retries; a denied or broken channel leaves the
 *    snapshot at STANDARD with an explicit note.
 *
 * Everything in this class is fail-soft: a hostile, locked-down or partially readable device yields
 * a snapshot with `null` unknowns and honest notes, never an exception and never a fabricated
 * "protected" state.
 */
class TitanPrivilegeGate(context: Context) {

    private val appContext: Context = context.applicationContext

    /**
     * Builds the passive privilege snapshot at [nowMillis].
     *
     * Never throws, never prompts and never executes a privileged command. Each individual probe is
     * guarded so one unreadable source (for example a blocked hidden API) cannot blank the whole
     * snapshot.
     */
    fun passiveSnapshot(nowMillis: Long): TitanPrivilegeSnapshot {
        val at = nowMillis.coerceAtLeast(1L)
        return try {
            val suPaths = detectSuPaths()
            val rootManagers = detectRootManagers()
            val rootKind = when {
                suPaths.isEmpty() -> TitanRootKind.NONE
                rootManagers.isNotEmpty() -> TitanRootKind.MANAGED
                else -> TitanRootKind.DIRTY
            }
            val selinuxRaw = readGetenforce()?.trim()?.takeIf { it.isNotEmpty() }?.take(MAX_SELINUX_RAW_CHARS)
            val build = TitanBuildIntegrity(
                testKeys = buildHasTestKeys(),
                debuggableBuild = parseDebuggable(readGetprop(PROPERTY_DEBUGGABLE)?.trim()),
                selinuxEnforcing = parseSelinuxEnforcing(selinuxRaw),
                adbTcpExposed = parseAdbTcpExposed(readGetprop(PROPERTY_ADB_TCP_PORT)?.trim()),
                selinuxRaw = selinuxRaw,
            )
            val shizukuInstalled = packageInstalled(SHIZUKU_PACKAGE)
            val shizukuBridge = shizukuBridgeReachable()
            TitanPrivilegeSnapshot(
                level = TitanPrivilegeLevel.STANDARD,
                rootKind = rootKind,
                suPaths = suPaths,
                rootManagers = rootManagers,
                rootShellConfirmed = false,
                shizukuInstalled = shizukuInstalled,
                shizukuBridgeAvailable = shizukuBridge,
                build = build,
                checkedAtMillis = at,
                notes = passiveNotes(suPaths, rootKind, build, shizukuInstalled, shizukuBridge),
            )
        } catch (error: Throwable) {
            Log.w(TAG, "titan_gate_snapshot_failed:${error.javaClass.simpleName}")
            TitanPrivilegeSnapshot.unchecked(at)
        }
    }

    /**
     * Runs the explicit root confirmation probe through [shell] and returns the resulting snapshot.
     *
     * Only when the probe output contains `uid=0(root)` does the level become
     * [TitanPrivilegeLevel.ROOT] with `rootShellConfirmed = true`. In every other case (denied
     * prompt, timeout, missing `su`, non-root identity) the level is forced back to
     * [TitanPrivilegeLevel.STANDARD] and [TitanTextKeys.NOTE_ROOT_SHELL_DENIED] is recorded. The
     * probe is executed at most once per call; there is no automatic retry loop.
     */
    fun confirmRoot(
        snapshot: TitanPrivilegeSnapshot,
        shell: TitanShell,
        nowMillis: Long,
    ): TitanPrivilegeSnapshot {
        val at = nowMillis.coerceAtLeast(1L)
        val probe = try {
            shell.probeRoot()
        } catch (error: Throwable) {
            Log.w(TAG, "titan_root_probe_failed:${error.javaClass.simpleName}")
            null
        }
        val confirmed = probe != null && probe.ok && probe.output.contains(ROOT_UID_MARKER)
        return try {
            if (confirmed) {
                snapshot.copy(
                    level = TitanPrivilegeLevel.ROOT,
                    rootShellConfirmed = true,
                    checkedAtMillis = at,
                    notes = withNote(
                        withoutNote(snapshot.notes, TitanTextKeys.NOTE_STANDARD_ONLY),
                        MessageRef(TitanTextKeys.NOTE_ROOT_DETECTED),
                    ),
                )
            } else {
                Log.w(TAG, "titan_root_probe_denied")
                snapshot.copy(
                    level = TitanPrivilegeLevel.STANDARD,
                    rootShellConfirmed = false,
                    checkedAtMillis = at,
                    notes = withNote(
                        withNote(snapshot.notes, MessageRef(TitanTextKeys.NOTE_STANDARD_ONLY)),
                        MessageRef(TitanTextKeys.NOTE_ROOT_SHELL_DENIED),
                    ),
                )
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan_root_confirmation_failed:${error.javaClass.simpleName}")
            TitanPrivilegeSnapshot.unchecked(at)
        }
    }

    // ------------------------------------------------------------------ passive probes

    private fun detectSuPaths(): List<String> = try {
        TitanShell.SU_CANDIDATES.filter { path -> fileExists(path) }.take(TitanPrivilegeSnapshot.MAX_PATHS)
    } catch (error: Throwable) {
        Log.w(TAG, "titan_gate_su_probe_failed:${error.javaClass.simpleName}")
        emptyList()
    }

    private fun detectRootManagers(): List<String> {
        val managers = LinkedHashSet<String>()
        try {
            for ((manager, markers) in ROOT_MANAGER_MARKERS) {
                if (markers.any { marker -> fileExists(marker) }) managers.add(manager)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan_gate_manager_marker_probe_failed:${error.javaClass.simpleName}")
        }
        try {
            for ((manager, packageName) in ROOT_MANAGER_PACKAGES) {
                if (packageInstalled(packageName)) managers.add(manager)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan_gate_manager_package_probe_failed:${error.javaClass.simpleName}")
        }
        return managers.take(TitanPrivilegeSnapshot.MAX_MANAGERS).toList()
    }

    private fun fileExists(path: String): Boolean = try {
        File(path).exists()
    } catch (_: Throwable) {
        false
    }

    /**
     * Guarded package lookup.
     *
     * The Binder call runs through [BoundedAndroidCall] so a wedged `PackageManager` cannot block the
     * Titan worker. A missing package, a hidden API denial and a timeout all report `false`; package
     * visibility restrictions (`<queries>`) can therefore only make detection more conservative,
     * never forge a finding.
     */
    private fun packageInstalled(packageName: String): Boolean = try {
        BoundedAndroidCall.call(PACKAGE_LOOKUP_TIMEOUT_MILLIS) {
            appContext.packageManager.getPackageInfo(packageName, 0)
            true
        }
    } catch (_: PlatformCallUnavailableException) {
        false
    } catch (_: Throwable) {
        false
    }

    private fun readGetenforce(): String? = readLocal(listOf(GETENFORCE_PROGRAM))

    private fun readGetprop(propertyName: String): String? = readLocal(listOf(GETPROP_PROGRAM, propertyName))

    private fun readLocal(argv: List<String>): String? {
        val outcome = TitanBoundedProcess.run(
            argv = argv,
            workingDirectory = null,
            timeoutMillis = LOCAL_PROBE_TIMEOUT_MILLIS,
            maxBytes = LOCAL_PROBE_CAP_BYTES,
        )
        return when {
            !outcome.started -> null
            outcome.timedOut -> null
            outcome.truncated -> null
            outcome.exitCode != 0 -> null
            else -> outcome.output
        }
    }

    private fun buildHasTestKeys(): Boolean = try {
        Build.TAGS?.contains(TEST_KEYS_TAG) == true
    } catch (_: Throwable) {
        false
    }

    /**
     * Reachability probe of the Shizuku binder bridge.
     *
     * `android.os.ServiceManager` is a hidden API. The lookup is wrapped in `catch (Throwable)`
     * because hidden-API enforcement, missing binder services and API-level differences all surface
     * as different throwable types here. On the vast majority of devices and API levels this returns
     * `false`, which is the honest answer: Shizuku presence is detected, but no command bridge is
     * claimed in this alpha.
     */
    private fun shizukuBridgeReachable(): Boolean = try {
        val serviceManagerClass = Class.forName(SERVICE_MANAGER_CLASS)
        val getService = serviceManagerClass.getMethod(GET_SERVICE_METHOD, String::class.java)
        getService.invoke(null, SHIZUKU_SERVICE_NAME) != null
    } catch (_: Throwable) {
        false
    }

    // ------------------------------------------------------------------ note composition

    private fun passiveNotes(
        suPaths: List<String>,
        rootKind: TitanRootKind,
        build: TitanBuildIntegrity,
        shizukuInstalled: Boolean,
        shizukuBridge: Boolean,
    ): List<MessageRef> {
        val notes = ArrayList<MessageRef>(MAX_PASSIVE_NOTES)
        if (suPaths.isNotEmpty()) notes.add(MessageRef(TitanTextKeys.NOTE_ROOT_DETECTED))
        if (rootKind == TitanRootKind.DIRTY) notes.add(MessageRef(TitanTextKeys.NOTE_DIRTY_ROOT))
        if (build.selinuxEnforcing == false) notes.add(MessageRef(TitanTextKeys.NOTE_SELINUX_PERMISSIVE))
        if (build.testKeys) notes.add(MessageRef(TitanTextKeys.NOTE_TEST_KEYS))
        if (build.adbTcpExposed == true) notes.add(MessageRef(TitanTextKeys.NOTE_ADB_EXPOSED))
        if (shizukuInstalled) notes.add(MessageRef(TitanTextKeys.NOTE_SHIZUKU_DETECTED))
        if (shizukuInstalled && !shizukuBridge) notes.add(MessageRef(TitanTextKeys.NOTE_SHIZUKU_BRIDGE_MISSING))
        // The passive level is always STANDARD. State it only when nothing else was found, so the
        // note list stays a finding list instead of repeating the displayed level on every device.
        if (notes.isEmpty()) notes.add(MessageRef(TitanTextKeys.NOTE_STANDARD_ONLY))
        return notes.take(TitanPrivilegeSnapshot.MAX_NOTES)
    }

    private fun withoutNote(notes: List<MessageRef>, key: String): List<MessageRef> =
        notes.filter { note -> note.key != key }

    private fun withNote(notes: List<MessageRef>, note: MessageRef): List<MessageRef> =
        if (notes.any { existing -> existing.key == note.key }) {
            notes
        } else {
            (notes + note).takeLast(TitanPrivilegeSnapshot.MAX_NOTES)
        }

    // ------------------------------------------------------------------ parsing helpers

    private fun parseDebuggable(raw: String?): Boolean? = when (raw) {
        "1" -> true
        "0" -> false
        else -> null
    }

    /**
     * Tri-state SELinux state: `true` only for `Enforcing`, `false` for `Permissive`/`Disabled`,
     * `null` when the state could not be read at all.
     */
    private fun parseSelinuxEnforcing(raw: String?): Boolean? {
        val value = raw.orEmpty()
        if (value.isEmpty()) return null
        return value.equals(SELINUX_ENFORCING, ignoreCase = true)
    }

    /** `true` only when the property parses to a positive port; `null` when it could not be read. */
    private fun parseAdbTcpExposed(raw: String?): Boolean? {
        if (raw == null) return null
        if (raw.isEmpty()) return false
        val port = raw.toIntOrNull() ?: return false
        return port > 0
    }

    private companion object {
        const val TAG = "GeDefenseTv"
        const val GETENFORCE_PROGRAM = "getenforce"
        const val GETPROP_PROGRAM = "getprop"
        const val PROPERTY_DEBUGGABLE = "ro.debuggable"
        const val PROPERTY_ADB_TCP_PORT = "service.adb.tcp.port"
        const val TEST_KEYS_TAG = "test-keys"
        const val SELINUX_ENFORCING = "Enforcing"
        const val SERVICE_MANAGER_CLASS = "android.os.ServiceManager"
        const val GET_SERVICE_METHOD = "getService"
        const val SHIZUKU_SERVICE_NAME = "shizuku"
        const val SHIZUKU_PACKAGE = "moe.shizuku.privileged.api"
        const val ROOT_UID_MARKER = "uid=0(root)"
        const val MAX_SELINUX_RAW_CHARS = 32
        const val MAX_PASSIVE_NOTES = 10
        const val LOCAL_PROBE_TIMEOUT_MILLIS = 2_000L
        const val LOCAL_PROBE_CAP_BYTES = 4 * 1024
        const val PACKAGE_LOOKUP_TIMEOUT_MILLIS = 1_500L

        /** Root-manager install markers; values are the stable ids reported in the snapshot. */
        val ROOT_MANAGER_MARKERS: Map<String, List<String>> = linkedMapOf(
            "magisk" to listOf("/data/adb/magisk", "/sbin/.magisk", "/data/adb/modules"),
            "kernelsu" to listOf("/data/adb/ksu"),
            "apatch" to listOf("/data/adb/ap"),
        )

        /** Root-manager packages; the manager ids stay identical to the marker ids. */
        val ROOT_MANAGER_PACKAGES: Map<String, String> = linkedMapOf(
            "magisk" to "com.topjohnwu.magisk",
            "kernelsu" to "me.weishu.kernelsu",
            "apatch" to "me.bmax.apatch",
            "supersu" to "eu.chainfire.supersu",
        )
    }
}
