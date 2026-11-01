package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.Settings
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanFimPolicy
import de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory
import de.visiongaia.gedefense.tv.vpn.BoundedAndroidCall
import de.visiongaia.gedefense.tv.vpn.PlatformCallUnavailableException

/**
 * Platform-level target guards of the response engine (hardening findings F-14 / F-07).
 *
 * These guards are deliberately separate from the domain [de.visiongaia.gedefense.tv.core.titan.response.TitanContainmentPolicy]:
 * the policy stays the single, pure no-brick gate, while this class adds device-specific facts that
 * only a live `PackageManager`/root shell can provide.
 */
internal class TitanTargetGuard(context: Context) {

    private val appContext: Context = context.applicationContext

    /**
     * Fail-closed platform guard for app-targeted actions.
     *
     * Returns the failure code to refuse with, or null when the target may pass on to the domain
     * policy (which still applies its own protected list). Only FREEZE_APP/RESTORE_APP are guarded.
     *
     * Two extra layers on top of the AOSP/Google-only domain list:
     *  - a target owned by a system/root UID (< [MIN_APP_UID]) is refused, so OEM system packages that
     *    are not in the domain list are unreachable too;
     *  - the resolved launcher, settings and IME home packages are refused even when an OEM ships them
     *    as normal third-party packages.
     *
     * Freeze fails closed: when the target UID cannot be resolved (not installed, invisible under
     * API 30+ package-visibility rules, or a bounded PackageManager timeout) nothing is frozen.
     * Restore stays available in that case, because blocking the inverse of a freeze is the larger
     * brick risk (the user must always be able to re-enable what Titan disabled).
     */
    fun refusal(action: TitanContainmentAction, packageName: String?): TitanActionFailure? {
        if (action != TitanContainmentAction.FREEZE_APP && action != TitanContainmentAction.RESTORE_APP) return null
        if (packageName == null) return TitanActionFailure.INVALID_TARGET
        val uid = resolveUid(packageName)
        if (uid == null) {
            return if (action == TitanContainmentAction.FREEZE_APP) TitanActionFailure.PROTECTED_TARGET else null
        }
        if (uid < MIN_APP_UID) return TitanActionFailure.PROTECTED_TARGET
        val criticalTarget = packageName == launcherHomePackage() ||
            packageName == settingsPackage() ||
            packageName == inputMethodPackage()
        return if (criticalTarget) TitanActionFailure.PROTECTED_TARGET else null
    }

    private fun resolveUid(packageName: String): Int? = try {
        BoundedAndroidCall.call(LOOKUP_TIMEOUT_MILLIS) {
            appContext.packageManager.getPackageInfo(packageName, 0).applicationInfo?.uid
        }
    } catch (_: PlatformCallUnavailableException) {
        null
    } catch (_: Throwable) {
        null
    }

    private fun launcherHomePackage(): String? = resolveActivityPackage(
        Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_HOME),
        PackageManager.MATCH_DEFAULT_ONLY,
    )

    private fun settingsPackage(): String? = resolveActivityPackage(
        Intent(Settings.ACTION_SETTINGS),
        PackageManager.MATCH_DEFAULT_ONLY,
    )

    private fun inputMethodPackage(): String? = try {
        BoundedAndroidCall.call(LOOKUP_TIMEOUT_MILLIS) {
            Settings.Secure.getString(appContext.contentResolver, Settings.Secure.DEFAULT_INPUT_METHOD)
        }?.substringBefore('/')?.takeIf { packageName -> PACKAGE_PATTERN.matches(packageName) }
    } catch (_: PlatformCallUnavailableException) {
        null
    } catch (_: Throwable) {
        null
    }

    private fun resolveActivityPackage(intent: Intent, flags: Int): String? = try {
        BoundedAndroidCall.call(LOOKUP_TIMEOUT_MILLIS) {
            appContext.packageManager.resolveActivity(intent, flags)?.activityInfo?.packageName
        }
    } catch (_: PlatformCallUnavailableException) {
        null
    } catch (_: Throwable) {
        null
    }

    private companion object {
        const val MIN_APP_UID = 10_000
        const val LOOKUP_TIMEOUT_MILLIS = 1_500L
        val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){1,15}")
    }
}

/**
 * Read-only pre-flight of the fixed quarantine vault path (hardening finding F-07).
 *
 * `TitanCommandFactory` always operates on the fixed [TitanFimPolicy.VAULT_PATH]. If that path were a
 * pre-planted symlink, `mkdir -p`/`mv`/`chmod` would act on its target instead of the vault. This
 * guard inspects the parent directory with the existing, allow-listed `ls` command and requires the
 * entry to be absent (it will be created with mode 700) or a plain directory.
 *
 * Residual risk, documented honestly: the inspection and `mkdir -p` are two separate root commands,
 * so a local attacker with shell/root access could still race a swap between them. The guard removes
 * the static pre-planted-symlink attack; closing the race completely needs a single atomic
 * allow-listed command in `:tv-core` (Lead-owned) and is a later hardening step.
 */
internal class TitanVaultGuard(private val shell: TitanShell) {

    /** Explicit refusal with an audit-safe detail tag; null means the path may be used/created. */
    data class Refusal(val failure: TitanActionFailure, val detail: String)

    /** Returns null when the vault path is absent or a plain directory. Never throws. */
    fun check(): Refusal? {
        val listing = shell.readTable(TitanCommandFactory.listDirectory(VAULT_PARENT))
            ?: return Refusal(TitanActionFailure.UNAVAILABLE, "vault-path-unreadable")
        val entry = findEntryLine(listing, VAULT_NAME) ?: return null
        return when (entry.first()) {
            'd' -> null
            'l' -> Refusal(TitanActionFailure.INVALID_TARGET, "vault-path-symlink")
            else -> Refusal(TitanActionFailure.INVALID_TARGET, "vault-path-not-directory")
        }
    }

    /**
     * Finds the `ls -ln` line of exactly [name] in the parent directory listing.
     *
     * Symlink lines are truncated at the ` -> ` marker before matching, so a symlink whose *target*
     * is the vault path is not mistaken for the vault entry itself.
     */
    private fun findEntryLine(listing: String, name: String): String? = listing.lineSequence()
        .map { line -> line.trim() }
        .firstOrNull { line ->
            val arrow = line.indexOf(" -> ")
            val entryPart = if (arrow >= 0) line.substring(0, arrow).trim() else line
            entryPart.endsWith(" $name")
        }

    private companion object {
        val VAULT_PARENT: String = TitanFimPolicy.VAULT_PATH.substringBeforeLast('/')
        val VAULT_NAME: String = TitanFimPolicy.VAULT_PATH.substringAfterLast('/')
    }
}

/**
 * Read-only process-absence probe (hardening finding F-03).
 *
 * `kill -0` is not a reliable absence proof: EPERM (exit 1) and a missing binary (exit 127) also exit
 * non-zero and would masquerade as a verified kill. This probe reads `/proc/<pid>/status` through the
 * confirmed root channel instead:
 *  - readable status => the process still exists => false;
 *  - `su` unavailable or timeout => the channel proves nothing => false;
 *  - healthy shell, exit 1 and the explicit "No such file or directory" error for the status file
 *    => the /proc entry is gone => true;
 *  - any other failure (permission denied, missing `cat`, I/O error) => false.
 */
internal class TitanProcessProbe(private val shell: TitanShell) {

    fun isGone(pid: Int): Boolean {
        val probe = shell.execute(TitanCommandFactory.readProcessStatus(pid))
        if (probe.ok) return false
        if (probe.timedOut || probe.failure != TitanActionFailure.COMMAND_FAILED) return false
        return probe.exitCode == CAT_FILE_ERROR_EXIT_CODE && probe.output.contains(NOT_FOUND_MARKER)
    }

    private companion object {
        /** `cat` exits 1 for a missing or unreadable file. */
        const val CAT_FILE_ERROR_EXIT_CODE = 1

        /** Toybox/busybox ENOENT text; the only failure accepted as proof of absence. */
        const val NOT_FOUND_MARKER = "No such file or directory"
    }
}
