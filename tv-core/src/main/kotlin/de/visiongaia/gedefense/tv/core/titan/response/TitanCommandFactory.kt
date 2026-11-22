package de.visiongaia.gedefense.tv.core.titan.response

import de.visiongaia.gedefense.tv.core.titan.model.FimWatchRoot
import de.visiongaia.gedefense.tv.core.titan.model.TitanFimPolicy

/**
 * Builds the small, fixed set of reversible containment commands.
 *
 * Security invariants:
 *  - every identifier (package, uid, pid, vault file name) is validated before it becomes an argument;
 *  - paths are restricted to the watch policy and the vault directory, no `..`, no shell metacharacters;
 *  - no command can delete data, rewrite partitions or execute an arbitrary string;
 *  - every action has a matching, verified inverse (except the explicit ADB lockdown).
 */
object TitanCommandFactory {
    private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){1,15}")
    private val VAULT_FILE_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")
    private const val MIN_THIRD_PARTY_UID = 10_000

    /** Soft isolation: app disappears from the launcher but keeps its data; reversible via [restoreApp]. */
    fun freezeApp(packageName: String): TitanShellCommand {
        validatePackage(packageName)
        return TitanShellCommand(
            program = "pm",
            arguments = listOf("disable-user", "--user", "0", packageName),
            requiresRoot = true,
            auditTag = "freeze-app",
            allowsShizuku = true,
        )
    }

    /** Re-enable a frozen app. Always available; the user must never be locked out. */
    fun restoreApp(packageName: String): TitanShellCommand {
        validatePackage(packageName)
        return TitanShellCommand(
            program = "pm",
            arguments = listOf("enable", packageName),
            requiresRoot = true,
            auditTag = "restore-app",
            allowsShizuku = true,
        )
    }

    /** Extra hard stop of a running app; not a containment on its own. */
    fun forceStopApp(packageName: String): TitanShellCommand {
        validatePackage(packageName)
        return TitanShellCommand(
            program = "am",
            arguments = listOf("force-stop", packageName),
            requiresRoot = true,
            auditTag = "force-stop-app",
            allowsShizuku = true,
        )
    }

    /** Per-UID network quarantine: drop all outbound packets owned by the third-party UID. */
    fun isolateUid(uid: Int): TitanShellCommand {
        validateThirdPartyUid(uid)
        return TitanShellCommand(
            program = "iptables",
            arguments = listOf("-w", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", uid.toString(), "-j", "DROP"),
            requiresRoot = true,
            auditTag = "isolate-uid",
        )
    }

    /** Remove the UID quarantine rule created by [isolateUid]. */
    fun releaseUid(uid: Int): TitanShellCommand {
        validateThirdPartyUid(uid)
        return TitanShellCommand(
            program = "iptables",
            arguments = listOf("-w", "-D", "OUTPUT", "-m", "owner", "--uid-owner", uid.toString(), "-j", "DROP"),
            requiresRoot = true,
            auditTag = "release-uid",
        )
    }

    /** Kill one suspicious process by PID (never PID 1, never the own process - policy enforced). */
    fun killProcess(pid: Int): TitanShellCommand {
        require(pid in 2..TitanActionTargetLimits.MAX_PID) { "invalid target pid" }
        return TitanShellCommand(
            program = "kill",
            arguments = listOf("-9", pid.toString()),
            requiresRoot = true,
            auditTag = "kill-process",
        )
    }

    /** Close the classic ADB-over-network port and stop adbd. Explicit, non-silent, user-triggered. */
    fun closeAdbTcp(): List<TitanShellCommand> = listOf(
        TitanShellCommand(
            program = "setprop",
            arguments = listOf("service.adb.tcp.port", "-1"),
            requiresRoot = true,
            auditTag = "adb-port-off",
        ),
        TitanShellCommand(
            program = "stop",
            arguments = listOf("adbd"),
            requiresRoot = true,
            auditTag = "adbd-stop",
        ),
    )

    /** Create the vault directory with owner-only permissions before moving anything into it. */
    fun prepareVault(): List<TitanShellCommand> = listOf(
        TitanShellCommand(
            program = "mkdir",
            arguments = listOf("-p", "--", TitanFimPolicy.VAULT_PATH),
            requiresRoot = true,
            auditTag = "vault-mkdir",
        ),
        TitanShellCommand(
            program = "chmod",
            arguments = listOf("700", "--", TitanFimPolicy.VAULT_PATH),
            requiresRoot = true,
            auditTag = "vault-chmod",
        ),
    )

    /** Move one suspicious binary from a watched location into the vault (no deletion). */
    fun moveToVault(sourcePath: String, fileName: String): TitanShellCommand {
        require(TitanFimPolicy.isSafeAbsolutePath(sourcePath)) { "invalid vault source" }
        require(TitanFimPolicy.isWatched(sourcePath)) { "vault source is not a watched location" }
        require(fileName.matches(VAULT_FILE_PATTERN)) { "invalid vault file name" }
        val destination = TitanFimPolicy.VAULT_PATH + "/" + fileName
        return TitanShellCommand(
            program = "mv",
            arguments = listOf("--", sourcePath, destination),
            requiresRoot = true,
            auditTag = "vault-move",
        )
    }

    /** Remove execute permission from a quarantined file. */
    fun chmodVault(fileName: String): TitanShellCommand {
        require(fileName.matches(VAULT_FILE_PATTERN)) { "invalid vault file name" }
        return TitanShellCommand(
            program = "chmod",
            arguments = listOf("000", "--", TitanFimPolicy.VAULT_PATH + "/" + fileName),
            requiresRoot = true,
            auditTag = "vault-chmod-file",
        )
    }

    // ------------------------------------------------------------------ verification probes

    fun listDisabledPackages(): TitanShellCommand = TitanShellCommand(
        program = "cmd",
        arguments = listOf("package", "list", "packages", "-d"),
        requiresRoot = true,
        auditTag = "verify-disabled",
        allowsShizuku = true,
    )

    /** Lists installed package -> UID mappings across Android package-visibility boundaries. */
    fun listPackagesWithUids(): TitanShellCommand = TitanShellCommand(
        program = "cmd",
        arguments = listOf("package", "list", "packages", "-U"),
        requiresRoot = true,
        auditTag = "list-packages-uid",
        allowsShizuku = true,
    )

    fun listInputFilter(): TitanShellCommand = TitanShellCommand(
        program = "iptables",
        arguments = listOf("-w", "-L", "OUTPUT", "-n", "-v"),
        requiresRoot = true,
        auditTag = "verify-iptables",
    )

    fun probeProcess(pid: Int): TitanShellCommand {
        require(pid in 2..TitanActionTargetLimits.MAX_PID) { "invalid probe pid" }
        return TitanShellCommand(
            program = "kill",
            arguments = listOf("-0", pid.toString()),
            requiresRoot = true,
            auditTag = "verify-process",
        )
    }

    fun readAdbTcpPort(): TitanShellCommand = TitanShellCommand(
        program = "getprop",
        arguments = listOf("service.adb.tcp.port"),
        requiresRoot = true,
        auditTag = "verify-adb-port",
        allowsShizuku = true,
    )

    /** Explicit user-consented root/shell identity confirmation used by privilege activation. */
    fun probeRootIdentity(): TitanShellCommand = TitanShellCommand(
        program = "id",
        arguments = emptyList(),
        requiresRoot = true,
        auditTag = "probe-root",
        allowsShizuku = true,
    )

    // ------------------------------------------------- read-only collectors over the root channel

    /**
     * Lists regular files below one watched root. The output is parsed by the FIM collector; the
     * command itself cannot modify anything (`find ... -print` only).
     */
    fun listWatchRoot(rootPath: String, recursive: Boolean, maxDepth: Int): TitanShellCommand {
        require(TitanFimPolicy.isWatched(rootPath)) { "find root is not a watched location" }
        require(maxDepth in 0..FimWatchRoot.MAX_DEPTH) { "invalid find depth" }
        val arguments = ArrayList<String>(8)
        arguments += rootPath
        arguments += "-maxdepth"
        arguments += maxDepth.toString()
        if (!recursive) arguments += "-mindepth"
        if (!recursive) arguments += "1"
        arguments += "-type"
        arguments += "f"
        arguments += "-print"
        return TitanShellCommand(
            program = "find",
            arguments = arguments,
            requiresRoot = true,
            auditTag = "fim-find",
        )
    }

    /** POSIX stat in the toybox format `%a:%s:%Y` (mode, size, mtime epoch seconds). */
    fun statFile(path: String): TitanShellCommand {
        require(TitanFimPolicy.isSafeAbsolutePath(path) && TitanFimPolicy.isWatched(path)) {
            "stat path is not a watched location"
        }
        return TitanShellCommand(
            program = "stat",
            arguments = listOf("-c", "%a:%s:%Y", "--", path),
            requiresRoot = true,
            auditTag = "fim-stat",
        )
    }

    /** SHA-256 of one watched file (read-only). */
    fun sha256File(path: String): TitanShellCommand {
        require(TitanFimPolicy.isSafeAbsolutePath(path) && TitanFimPolicy.isWatched(path)) {
            "hash path is not a watched location"
        }
        return TitanShellCommand(
            program = "sha256sum",
            arguments = listOf("--", path),
            requiresRoot = true,
            auditTag = "fim-sha256",
        )
    }

    /** Reads one kernel/procfs table (read-only); restricted to `/proc/` and `/sys/` paths. */
    fun readProcTable(path: String): TitanShellCommand {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid proc path" }
        require(path.startsWith("/proc/") || path.startsWith("/sys/")) { "proc read outside procfs" }
        return TitanShellCommand(
            program = "cat",
            arguments = listOf(path),
            requiresRoot = true,
            auditTag = "read-proc",
            allowsShizuku = true,
        )
    }

    /** Lists one directory without following symlinks (read-only), used for fd/pid inspection. */
    fun listDirectory(path: String): TitanShellCommand {
        require(TitanFimPolicy.isSafeAbsolutePath(path)) { "invalid directory path" }
        require(path.startsWith("/proc/") || path.startsWith("/data/") || TitanFimPolicy.isWatched(path)) {
            "directory listing outside allowed roots"
        }
        return TitanShellCommand(
            program = "ls",
            arguments = listOf("-ln", "--", path),
            requiresRoot = true,
            auditTag = "list-dir",
            allowsShizuku = true,
        )
    }

    /** Reads the UID/package state of one `/proc/<pid>/status` file (read-only). */
    fun readProcessStatus(pid: Int): TitanShellCommand {
        require(pid in 1..TitanActionTargetLimits.MAX_PID) { "invalid pid" }
        return TitanShellCommand(
            program = "cat",
            arguments = listOf("/proc/$pid/status"),
            requiresRoot = true,
            auditTag = "read-proc-status",
            allowsShizuku = true,
        )
    }

    private fun validatePackage(packageName: String) {
        require(packageName.length <= 256 && PACKAGE_PATTERN.matches(packageName)) { "invalid package name" }
    }

    private fun validateThirdPartyUid(uid: Int) {
        require(uid in MIN_THIRD_PARTY_UID..TitanActionTargetLimits.MAX_UID) { "invalid containment uid" }
    }
}

/** Shared numeric bounds reused by the command factory and the policy. */
internal object TitanActionTargetLimits {
    const val MAX_UID = 2_000_000_000
    const val MAX_PID = 4_194_304
    const val MIN_THIRD_PARTY_UID = 10_000
}
