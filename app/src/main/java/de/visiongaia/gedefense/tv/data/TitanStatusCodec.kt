package de.visiongaia.gedefense.tv.data

import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanBuildIntegrity
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanRootKind
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus

/**
 * Persistence of the composed [TitanStatus] plus its privilege evidence and the compact module
 * counters.
 *
 * Honesty invariants:
 *  - the reconstructed `TitanStatus` always has `sockets = null` and `fim = null`: live observation
 *    rows are never persisted, only counters (the UI must render counts as "last known", not as a
 *    fresh clean result);
 *  - an elevated level is only reconstructed when the matching privilege evidence is valid; a
 *    corrupt/foreign level block yields `null` instead of a claimed privilege;
 *  - the effective capabilities/visibility are re-derived from the reconstructed privilege snapshot,
 *    so a manipulated capability list can never unlock a capability.
 */
internal class TitanStatusCodec(
    private val prefs: TitanPrefs,
    private val deviceId: String,
    private val witness: TitanWitnessCodec,
) {

    fun load(deviceId: String): TitanStatus? = try {
        loadInternal(deviceId)
    } catch (_: Throwable) {
        null
    }

    private fun loadInternal(deviceId: String): TitanStatus? {
        if (prefs.readInt(KEY_VERSION) != TitanPrefs.FORMAT_VERSION) return null
        val storedDevice = prefs.readString(KEY_DEVICE)
        if (!storedDevice.isNullOrBlank() && deviceId.isNotBlank() && storedDevice != deviceId) return null
        val storedLevel = parseLevel(prefs.readString(KEY_LEVEL)) ?: return null
        val outcome = parseOutcome(prefs.readString(KEY_OUTCOME)) ?: return null
        val lastScanAt = prefs.readLong(KEY_LAST_SCAN_AT)?.coerceAtLeast(0L) ?: return null
        val activeContainments = prefs.readInt(KEY_CONTAINMENTS)?.coerceIn(0, MAX_COUNT) ?: 0
        val privilege = loadPrivilege()
        // A non-standard level without valid evidence must never be claimed after a restart.
        if (storedLevel != TitanPrivilegeLevel.STANDARD && privilege == null) return null
        val status = TitanStatus(
            level = privilege?.level ?: storedLevel,
            visibility = TitanCapabilityMatrix.effectiveVisibility(privilege),
            capabilities = TitanCapabilityMatrix.effectiveCapabilities(privilege),
            privilege = privilege,
            sockets = null,
            fim = null,
            witness = witness.load(),
            activeContainments = activeContainments,
            lastScanAtMillis = lastScanAt,
            lastScanOutcome = outcome,
            notes = TitanNoteCodec.decode(prefs.readString(KEY_NOTES)),
            attentionRequired = prefs.readBoolean(KEY_ATTENTION) ?: false,
        )
        return status
    }

    fun save(status: TitanStatus) {
        try {
            val editor = prefs.editor()
            editor.putInt(KEY_VERSION, TitanPrefs.FORMAT_VERSION)
            if (deviceId.isNotBlank()) editor.putString(KEY_DEVICE, deviceId)
            editor.putString(KEY_LEVEL, status.level.name)
            editor.putString(KEY_VISIBILITY, status.visibility.name)
            editor.putString(KEY_CAPABILITIES, status.capabilities.joinToString(",") { it.id })
            editor.putLong(KEY_LAST_SCAN_AT, status.lastScanAtMillis.coerceAtLeast(0L))
            editor.putString(KEY_OUTCOME, status.lastScanOutcome.name)
            editor.putInt(KEY_CONTAINMENTS, status.activeContainments.coerceIn(0, MAX_COUNT))
            editor.putBoolean(KEY_ATTENTION, status.attentionRequired)
            writeNotes(editor, KEY_NOTES, status.notes)
            writePrivilege(editor, status.privilege)
            // Only a live pass overwrites the counters. A cold, re-saved status (snapshots null)
            // keeps the last known counts instead of wiping them.
            status.sockets?.let { writeSocketSummary(editor, it) }
            status.fim?.let { writeFimSummary(editor, it) }
            witness.write(editor, status.witness)
            prefs.commit(editor)
        } catch (_: Throwable) {
            // Fail-soft: Titan must never crash because preferences are full or corrupted.
        }
    }

    // ---------------------------------------------------------------- module counters

    fun loadSocketSummary(): TitanSocketSummary? = try {
        loadSocketSummaryInternal()
    } catch (_: Throwable) {
        null
    }

    private fun loadSocketSummaryInternal(): TitanSocketSummary? {
        if (prefs.readInt(KEY_SOCK_VERSION) != TitanPrefs.FORMAT_VERSION) return null
        val total = prefs.readInt(KEY_SOCK_TOTAL) ?: return null
        val attributable = prefs.readInt(KEY_SOCK_ATTRIBUTABLE) ?: return null
        val suspicious = prefs.readInt(KEY_SOCK_SUSPICIOUS) ?: return null
        val capturedAt = prefs.readLong(KEY_SOCK_CAPTURED_AT)?.takeIf { it > 0L } ?: return null
        val visibility = parseVisibility(prefs.readString(KEY_SOCK_VISIBILITY)) ?: return null
        if (total !in 0..MAX_COUNT || attributable !in 0..total || suspicious !in 0..MAX_COUNT) return null
        return TitanSocketSummary(
            totalSockets = total,
            attributableSockets = attributable,
            suspiciousCount = suspicious,
            capturedAtMillis = capturedAt,
            visibility = visibility,
            truncated = prefs.readBoolean(KEY_SOCK_TRUNCATED) ?: false,
            note = TitanNoteCodec.decodeSingle(prefs.readString(KEY_SOCK_NOTE)),
        )
    }

    fun loadFimSummary(): TitanFimSummary? = try {
        loadFimSummaryInternal()
    } catch (_: Throwable) {
        null
    }

    private fun loadFimSummaryInternal(): TitanFimSummary? {
        if (prefs.readInt(KEY_FIM_VERSION) != TitanPrefs.FORMAT_VERSION) return null
        val capturedAt = prefs.readLong(KEY_FIM_CAPTURED_AT)?.takeIf { it > 0L } ?: return null
        val visibility = parseVisibility(prefs.readString(KEY_FIM_VISIBILITY)) ?: return null
        val newFiles = prefs.readInt(KEY_FIM_NEW) ?: return null
        val modifiedFiles = prefs.readInt(KEY_FIM_MODIFIED) ?: return null
        val unreadableFiles = prefs.readInt(KEY_FIM_UNREADABLE) ?: return null
        val scannedFiles = prefs.readInt(KEY_FIM_SCANNED) ?: return null
        if (listOf(newFiles, modifiedFiles, unreadableFiles, scannedFiles).any { it !in 0..MAX_COUNT }) return null
        return TitanFimSummary(
            baselineCreated = prefs.readBoolean(KEY_FIM_BASELINE_CREATED) ?: false,
            newFiles = newFiles,
            modifiedFiles = modifiedFiles,
            unreadableFiles = unreadableFiles,
            scannedFiles = scannedFiles,
            capturedAtMillis = capturedAt,
            baselineAtMillis = prefs.readLong(KEY_FIM_BASELINE_AT)?.takeIf { it > 0L },
            visibility = visibility,
            truncated = prefs.readBoolean(KEY_FIM_TRUNCATED) ?: false,
            note = TitanNoteCodec.decodeSingle(prefs.readString(KEY_FIM_NOTE)),
        )
    }

    private fun writeSocketSummary(editor: SharedPreferences.Editor, snapshot: SocketSnapshot) {
        editor.putInt(KEY_SOCK_VERSION, TitanPrefs.FORMAT_VERSION)
        editor.putInt(KEY_SOCK_TOTAL, snapshot.totalSockets.coerceIn(0, MAX_COUNT))
        editor.putInt(KEY_SOCK_ATTRIBUTABLE, snapshot.attributableSockets.coerceIn(0, MAX_COUNT))
        editor.putInt(KEY_SOCK_SUSPICIOUS, snapshot.suspiciousCount.coerceIn(0, MAX_COUNT))
        editor.putLong(KEY_SOCK_CAPTURED_AT, snapshot.capturedAtMillis.coerceAtLeast(1L))
        editor.putString(KEY_SOCK_VISIBILITY, snapshot.visibility.name)
        editor.putBoolean(KEY_SOCK_TRUNCATED, snapshot.truncated)
        writeNote(editor, KEY_SOCK_NOTE, TitanNoteCodec.encodeSingle(snapshot.note))
    }

    private fun writeFimSummary(editor: SharedPreferences.Editor, snapshot: FimSnapshot) {
        editor.putInt(KEY_FIM_VERSION, TitanPrefs.FORMAT_VERSION)
        editor.putBoolean(KEY_FIM_BASELINE_CREATED, snapshot.baselineCreated)
        editor.putInt(KEY_FIM_NEW, snapshot.newFiles.coerceIn(0, MAX_COUNT))
        editor.putInt(KEY_FIM_MODIFIED, snapshot.modifiedFiles.coerceIn(0, MAX_COUNT))
        editor.putInt(KEY_FIM_UNREADABLE, snapshot.unreadableFiles.coerceIn(0, MAX_COUNT))
        editor.putInt(KEY_FIM_SCANNED, snapshot.scannedFiles.coerceIn(0, MAX_COUNT))
        editor.putLong(KEY_FIM_CAPTURED_AT, snapshot.capturedAtMillis.coerceAtLeast(1L))
        val baselineAt = snapshot.baselineAtMillis
        if (baselineAt != null && baselineAt > 0L) {
            editor.putLong(KEY_FIM_BASELINE_AT, baselineAt)
        } else {
            editor.remove(KEY_FIM_BASELINE_AT)
        }
        editor.putString(KEY_FIM_VISIBILITY, snapshot.visibility.name)
        editor.putBoolean(KEY_FIM_TRUNCATED, snapshot.truncated)
        writeNote(editor, KEY_FIM_NOTE, TitanNoteCodec.encodeSingle(snapshot.note))
    }

    // -------------------------------------------------------------------- privilege

    private fun writePrivilege(editor: SharedPreferences.Editor, privilege: TitanPrivilegeSnapshot?) {
        if (privilege == null) {
            for (key in PRIVILEGE_KEYS) editor.remove(key)
            return
        }
        editor.putInt(KEY_PRIV_VERSION, TitanPrefs.FORMAT_VERSION)
        editor.putString(KEY_PRIV_LEVEL, privilege.level.name)
        editor.putString(KEY_PRIV_ROOT_KIND, privilege.rootKind.name)
        editor.putString(KEY_PRIV_SU_PATHS, privilege.suPaths.joinToString("\n"))
        editor.putString(KEY_PRIV_MANAGERS, privilege.rootManagers.joinToString(","))
        editor.putBoolean(KEY_PRIV_ROOT_CONFIRMED, privilege.rootShellConfirmed)
        editor.putBoolean(KEY_PRIV_SHIZUKU_INSTALLED, privilege.shizukuInstalled)
        editor.putBoolean(KEY_PRIV_SHIZUKU_BRIDGE, privilege.shizukuBridgeAvailable)
        prefs.putTriState(editor, KEY_PRIV_BUILD_TEST_KEYS, privilege.build.testKeys)
        prefs.putTriState(editor, KEY_PRIV_BUILD_DEBUGGABLE, privilege.build.debuggableBuild)
        prefs.putTriState(editor, KEY_PRIV_BUILD_SELINUX, privilege.build.selinuxEnforcing)
        prefs.putTriState(editor, KEY_PRIV_BUILD_ADB_TCP, privilege.build.adbTcpExposed)
        val raw = privilege.build.selinuxRaw
        if (raw != null) editor.putString(KEY_PRIV_BUILD_SELINUX_RAW, raw) else editor.remove(KEY_PRIV_BUILD_SELINUX_RAW)
        editor.putLong(KEY_PRIV_CHECKED_AT, privilege.checkedAtMillis.coerceAtLeast(1L))
        writeNotes(editor, KEY_PRIV_NOTES, privilege.notes)
    }

    private fun loadPrivilege(): TitanPrivilegeSnapshot? {
        if (prefs.readInt(KEY_PRIV_VERSION) != TitanPrefs.FORMAT_VERSION) return null
        val checkedAt = prefs.readLong(KEY_PRIV_CHECKED_AT)?.takeIf { it > 0L } ?: return null
        val level = parseLevel(prefs.readString(KEY_PRIV_LEVEL)) ?: return null
        val rootKind = parseRootKind(prefs.readString(KEY_PRIV_ROOT_KIND)) ?: return null
        val build = TitanBuildIntegrity(
            testKeys = prefs.readTriState(KEY_PRIV_BUILD_TEST_KEYS) ?: false,
            debuggableBuild = prefs.readTriState(KEY_PRIV_BUILD_DEBUGGABLE),
            selinuxEnforcing = prefs.readTriState(KEY_PRIV_BUILD_SELINUX),
            adbTcpExposed = prefs.readTriState(KEY_PRIV_BUILD_ADB_TCP),
            selinuxRaw = sanitiseSelinuxRaw(prefs.readString(KEY_PRIV_BUILD_SELINUX_RAW)),
        )
        return try {
            TitanPrivilegeSnapshot(
                level = level,
                rootKind = rootKind,
                suPaths = parseSuPaths(prefs.readString(KEY_PRIV_SU_PATHS)),
                rootManagers = parseManagers(prefs.readString(KEY_PRIV_MANAGERS)),
                rootShellConfirmed = prefs.readBoolean(KEY_PRIV_ROOT_CONFIRMED) ?: false,
                shizukuInstalled = prefs.readBoolean(KEY_PRIV_SHIZUKU_INSTALLED) ?: false,
                shizukuBridgeAvailable = prefs.readBoolean(KEY_PRIV_SHIZUKU_BRIDGE) ?: false,
                build = build,
                checkedAtMillis = checkedAt,
                notes = TitanNoteCodec.decode(prefs.readString(KEY_PRIV_NOTES)),
            )
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    // -------------------------------------------------------------- note/value helpers

    private fun writeNotes(editor: SharedPreferences.Editor, key: String, notes: List<de.visiongaia.gedefense.tv.core.model.MessageRef>) {
        val encoded = TitanNoteCodec.encode(notes)
        if (encoded.isEmpty()) editor.remove(key) else editor.putString(key, encoded)
    }

    private fun writeNote(editor: SharedPreferences.Editor, key: String, encoded: String?) {
        if (encoded == null) editor.remove(key) else editor.putString(key, encoded)
    }

    // ------------------------------------------------------------------- sanitisation

    private fun parseSuPaths(raw: String?): List<String> {
        if (raw.isNullOrEmpty()) return emptyList()
        val paths = ArrayList<String>(4)
        for (line in raw.lineSequence()) {
            if (paths.size >= TitanPrivilegeSnapshot.MAX_PATHS) break
            if (line.length !in 1..256) continue
            if (!line.startsWith("/")) continue
            // su paths are shown verbatim in the UI: only printable ASCII, no spaces/control chars.
            if (line.any { character -> character.code !in 0x21..0x7E }) continue
            if (paths.contains(line)) continue
            paths += line
        }
        return paths
    }

    private fun parseManagers(raw: String?): List<String> {
        if (raw.isNullOrEmpty()) return emptyList()
        val managers = ArrayList<String>(4)
        for (candidate in raw.split(',')) {
            if (managers.size >= TitanPrivilegeSnapshot.MAX_MANAGERS) break
            if (!MANAGER_PATTERN.matches(candidate)) continue
            if (managers.contains(candidate)) continue
            managers += candidate
        }
        return managers
    }

    private fun sanitiseSelinuxRaw(raw: String?): String? {
        if (raw == null) return null
        val sanitised = raw.map { character -> if (character.code in 0x20..0x7E) character else ' ' }
            .joinToString("")
            .trim()
        return sanitised.takeIf { it.isNotEmpty() }?.take(MAX_SELINUX_RAW)
    }

    private fun parseLevel(name: String?): TitanPrivilegeLevel? = try {
        name?.let { TitanPrivilegeLevel.valueOf(it) }
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun parseRootKind(name: String?): TitanRootKind? = try {
        name?.let { TitanRootKind.valueOf(it) }
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun parseOutcome(name: String?): TitanScanOutcome? = try {
        name?.let { TitanScanOutcome.valueOf(it) }
    } catch (_: IllegalArgumentException) {
        null
    }

    private fun parseVisibility(name: String?): DataVisibility? = try {
        name?.let { DataVisibility.valueOf(it) }
    } catch (_: IllegalArgumentException) {
        null
    }

    private companion object {
        const val MAX_COUNT = 1_000_000
        const val MAX_SELINUX_RAW = 32
        val MANAGER_PATTERN = Regex("[a-z][a-z0-9-]{1,31}")

        // status block
        const val KEY_VERSION = "status.version"
        const val KEY_DEVICE = "status.device"
        const val KEY_LEVEL = "status.level"
        const val KEY_VISIBILITY = "status.visibility"
        const val KEY_CAPABILITIES = "status.capabilities"
        const val KEY_LAST_SCAN_AT = "status.last_scan_at"
        const val KEY_OUTCOME = "status.outcome"
        const val KEY_CONTAINMENTS = "status.containments"
        const val KEY_ATTENTION = "status.attention"
        const val KEY_NOTES = "status.notes"

        // socket counters
        const val KEY_SOCK_VERSION = "sock.version"
        const val KEY_SOCK_TOTAL = "sock.total"
        const val KEY_SOCK_ATTRIBUTABLE = "sock.attributable"
        const val KEY_SOCK_SUSPICIOUS = "sock.suspicious"
        const val KEY_SOCK_CAPTURED_AT = "sock.captured_at"
        const val KEY_SOCK_VISIBILITY = "sock.visibility"
        const val KEY_SOCK_TRUNCATED = "sock.truncated"
        const val KEY_SOCK_NOTE = "sock.note"

        // fim counters
        const val KEY_FIM_VERSION = "fim.version"
        const val KEY_FIM_BASELINE_CREATED = "fim.baseline_created"
        const val KEY_FIM_NEW = "fim.new"
        const val KEY_FIM_MODIFIED = "fim.modified"
        const val KEY_FIM_UNREADABLE = "fim.unreadable"
        const val KEY_FIM_SCANNED = "fim.scanned"
        const val KEY_FIM_CAPTURED_AT = "fim.captured_at"
        const val KEY_FIM_BASELINE_AT = "fim.baseline_at"
        const val KEY_FIM_VISIBILITY = "fim.visibility"
        const val KEY_FIM_TRUNCATED = "fim.truncated"
        const val KEY_FIM_NOTE = "fim.note"

        // privilege block
        const val KEY_PRIV_VERSION = "priv.version"
        const val KEY_PRIV_LEVEL = "priv.level"
        const val KEY_PRIV_ROOT_KIND = "priv.root_kind"
        const val KEY_PRIV_SU_PATHS = "priv.su_paths"
        const val KEY_PRIV_MANAGERS = "priv.managers"
        const val KEY_PRIV_ROOT_CONFIRMED = "priv.root_confirmed"
        const val KEY_PRIV_SHIZUKU_INSTALLED = "priv.shizuku_installed"
        const val KEY_PRIV_SHIZUKU_BRIDGE = "priv.shizuku_bridge"
        const val KEY_PRIV_BUILD_TEST_KEYS = "priv.build.test_keys"
        const val KEY_PRIV_BUILD_DEBUGGABLE = "priv.build.debuggable"
        const val KEY_PRIV_BUILD_SELINUX = "priv.build.selinux"
        const val KEY_PRIV_BUILD_ADB_TCP = "priv.build.adb_tcp"
        const val KEY_PRIV_BUILD_SELINUX_RAW = "priv.build.selinux_raw"
        const val KEY_PRIV_CHECKED_AT = "priv.checked_at"
        const val KEY_PRIV_NOTES = "priv.notes"

        val PRIVILEGE_KEYS = arrayOf(
            KEY_PRIV_VERSION,
            KEY_PRIV_LEVEL,
            KEY_PRIV_ROOT_KIND,
            KEY_PRIV_SU_PATHS,
            KEY_PRIV_MANAGERS,
            KEY_PRIV_ROOT_CONFIRMED,
            KEY_PRIV_SHIZUKU_INSTALLED,
            KEY_PRIV_SHIZUKU_BRIDGE,
            KEY_PRIV_BUILD_TEST_KEYS,
            KEY_PRIV_BUILD_DEBUGGABLE,
            KEY_PRIV_BUILD_SELINUX,
            KEY_PRIV_BUILD_ADB_TCP,
            KEY_PRIV_BUILD_SELINUX_RAW,
            KEY_PRIV_CHECKED_AT,
            KEY_PRIV_NOTES,
        )
    }
}
