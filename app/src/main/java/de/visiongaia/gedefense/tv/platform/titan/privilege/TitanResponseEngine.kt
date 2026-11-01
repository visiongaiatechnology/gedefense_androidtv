package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.Context
import android.util.Log
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionDecision
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionRequest
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionTarget
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanDecisionKeys
import de.visiongaia.gedefense.tv.core.titan.model.TitanFimPolicy
import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry
import de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory
import de.visiongaia.gedefense.tv.core.titan.response.TitanContainmentPolicy
import de.visiongaia.gedefense.tv.core.titan.response.TitanShellCommand
import java.util.UUID

/**
 * Result of one quarantine attempt: the audit result plus the vault metadata row.
 *
 * [entry] is non-null exactly when the binary was moved into the vault; a later `chmod 000` failure
 * still yields an entry (the object is quarantined but not fully neutralised) together with a
 * failed [result].
 */
data class QuarantineOutcome(
    val result: TitanActionResult,
    val entry: TitanVaultEntry?,
)

/**
 * Fail-closed execution layer of the Titan response engine.
 *
 * Two phases are kept strictly apart:
 *
 *  1. [evaluate] asks the domain [TitanContainmentPolicy] (protected packages, UID/PID bounds,
 *     capability set, active-containment and rate limits) and adds the platform guards of
 *     [TitanTargetGuard]: an action that addresses the running app itself, a system-UID package or the
 *     device's launcher/settings/IME home package is refused even when the AOSP-only domain list does
 *     not cover it. Freeze fails closed when the target identity cannot be resolved.
 *  2. [execute] maps the allowed action to the fixed [TitanCommandFactory] command(s), runs them
 *     through [TitanShell] and verifies the effect with a second, read-only probe
 *     ([TitanProcessProbe] for process absence).
 *
 * Invariants:
 *  - no command is executed before `TitanActionDecision.allowed`;
 *  - every attempt (allowed or refused) is counted through [TitanContainmentPolicy.recordExecution];
 *  - `ok` never claims an unverified effect: a command that ran but whose effect could not be
 *    confirmed reports `failure = VERIFICATION_FAILED`;
 *  - [TitanActionResult.detail] carries only audit tags, exit codes, the verification boolean and a
 *    failure code - never raw shell output and never secrets;
 *  - methods never throw for an unavailable shell, a missing root channel or hostile `su` output.
 *
 * The quarantine flow is gated by [TitanCapability.QUARANTINE_VAULT] and by the domain
 * [TitanFimPolicy]: only absolute paths inside the fixed watch roots can ever be moved.
 */
class TitanResponseEngine(
    context: Context,
    private val shell: TitanShell,
    private val policy: TitanContainmentPolicy,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {

    private val appContext: Context = context.applicationContext
    private val selfPackage: String = appContext.packageName
    private val selfUid: Int = android.os.Process.myUid()
    private val targetGuard: TitanTargetGuard = TitanTargetGuard(appContext)
    private val vaultGuard: TitanVaultGuard = TitanVaultGuard(shell)
    private val processProbe: TitanProcessProbe = TitanProcessProbe(shell)

    /**
     * Evaluates one action without executing anything.
     *
     * The returned decision is always fail-closed: an internal policy exception becomes
     * [TitanActionFailure.NOT_AUTHORIZED] instead of an allowed action.
     */
    fun evaluate(
        request: TitanActionRequest,
        capabilities: Set<TitanCapability>,
        activeContainments: Int,
    ): TitanActionDecision {
        val base = try {
            policy.evaluate(capabilities, request, activeContainments)
        } catch (error: Throwable) {
            Log.w(TAG, "titan_decision_failed:${error.javaClass.simpleName}")
            return TitanActionDecision(
                allowed = false,
                failure = TitanActionFailure.NOT_AUTHORIZED,
                reasonKey = MessageRef(TitanDecisionKeys.NOT_AUTHORIZED),
                requiredCapability = null,
            )
        }
        if (!base.allowed) return base
        if (isSelfTarget(request)) {
            return TitanActionDecision(
                allowed = false,
                failure = TitanActionFailure.PROTECTED_TARGET,
                reasonKey = MessageRef(TitanDecisionKeys.PROTECTED),
                requiredCapability = base.requiredCapability ?: policy.requiredCapability(request.action),
            )
        }
        val platformRefusal = targetGuard.refusal(request.action, request.target.packageName)
        if (platformRefusal != null) {
            return TitanActionDecision(
                allowed = false,
                failure = platformRefusal,
                reasonKey = MessageRef(
                    if (platformRefusal == TitanActionFailure.INVALID_TARGET) {
                        TitanDecisionKeys.INVALID_TARGET
                    } else {
                        TitanDecisionKeys.PROTECTED
                    },
                ),
                requiredCapability = base.requiredCapability ?: policy.requiredCapability(request.action),
            )
        }
        return base
    }

    /**
     * Evaluates and, only when allowed, executes one containment action with post-execution
     * verification. Never throws; every attempt is rate-limit counted.
     */
    fun execute(
        request: TitanActionRequest,
        capabilities: Set<TitanCapability>,
        activeContainments: Int,
    ): TitanActionResult {
        val at = clock().coerceAtLeast(1L)
        val decision = evaluate(request, capabilities, activeContainments)
        try {
            policy.recordExecution()
        } catch (error: Throwable) {
            Log.w(TAG, "titan_action_ledger_failed:${error.javaClass.simpleName}")
        }
        if (!decision.allowed) {
            return TitanActionResult(
                action = request.action,
                target = request.target,
                executedAtMillis = at,
                ok = false,
                verified = false,
                failure = decision.failure ?: TitanActionFailure.NOT_AUTHORIZED,
                detail = "decision=${decision.failure?.name?.lowercase() ?: "refused"} key=${decision.reasonKey.key}",
            )
        }
        return try {
            val commands = try {
                commandsFor(request)
            } catch (_: IllegalArgumentException) {
                return TitanActionResult(
                    action = request.action,
                    target = request.target,
                    executedAtMillis = at,
                    ok = false,
                    verified = false,
                    failure = TitanActionFailure.INVALID_TARGET,
                    detail = "invalid-target",
                )
            }
            val results = shell.executeAll(commands)
            val failed = results.firstOrNull { result -> !result.ok }
            if (failed != null) {
                return TitanActionResult(
                    action = request.action,
                    target = request.target,
                    executedAtMillis = at,
                    ok = false,
                    verified = false,
                    failure = failed.failure ?: TitanActionFailure.COMMAND_FAILED,
                    detail = commandDetail(commands, results, verify = false, failure = failed.failure),
                )
            }
            if (verifyEffect(request)) {
                TitanActionResult(
                    action = request.action,
                    target = request.target,
                    executedAtMillis = at,
                    ok = true,
                    verified = true,
                    failure = null,
                    detail = commandDetail(commands, results, verify = true, failure = null),
                )
            } else {
                TitanActionResult(
                    action = request.action,
                    target = request.target,
                    executedAtMillis = at,
                    ok = false,
                    verified = false,
                    failure = TitanActionFailure.VERIFICATION_FAILED,
                    detail = commandDetail(commands, results, verify = false, failure = TitanActionFailure.VERIFICATION_FAILED),
                )
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan_action_failed:${error.javaClass.simpleName}")
            TitanActionResult(
                action = request.action,
                target = request.target,
                executedAtMillis = at,
                ok = false,
                verified = false,
                failure = TitanActionFailure.UNAVAILABLE,
                detail = "engine-error",
            )
        }
    }

    /**
     * Moves one suspicious file from a watched location into the quarantine vault, removes its
     * execute permission and returns the metadata row for the local store.
     *
     * Gated by [TitanCapability.QUARANTINE_VAULT]; the capability set must be passed explicitly so
     * an unconfirmed root channel can never quarantine anything. Only paths inside
     * [TitanFimPolicy.DEFAULT_ROOTS] are accepted, so a caller can never pivot the vault into a
     * system path. Before the first root command, [TitanVaultGuard] verifies that the fixed vault
     * path is not a pre-planted symlink/non-directory; an unsafe path aborts the action. Nothing is
     * ever deleted.
     *
     * Note: tv-core 0.3.0-alpha1 has no dedicated vault action in [TitanContainmentAction]; the
     * reusable reversible containment kind [QUARANTINE_RESULT_ACTION] is used for the audit result
     * while the `vault-*` audit tags in [TitanActionResult.detail] and the [TitanVaultEntry] identify
     * the actual operation.
     */
    fun quarantine(
        sourcePath: String,
        sha256: String,
        sizeBytes: Long,
        permissions: String?,
        capabilities: Set<TitanCapability> = emptySet(),
    ): QuarantineOutcome {
        val at = clock().coerceAtLeast(1L)
        val target = TitanActionTarget(label = sourcePath.take(MAX_LABEL_CHARS))
        try {
            policy.recordExecution()
        } catch (error: Throwable) {
            Log.w(TAG, "titan_quarantine_ledger_failed:${error.javaClass.simpleName}")
        }
        if (TitanCapability.QUARANTINE_VAULT !in capabilities) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.NOT_AUTHORIZED, "capability-missing"),
                entry = null,
            )
        }
        if (!TitanFimPolicy.isSafeAbsolutePath(sourcePath) || !TitanFimPolicy.isWatched(sourcePath)) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.INVALID_TARGET, "source-outside-watch"),
                entry = null,
            )
        }
        if (!SHA256_PATTERN.matches(sha256)) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.INVALID_TARGET, "hash-invalid"),
                entry = null,
            )
        }
        if (sizeBytes < 0L) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.INVALID_TARGET, "size-invalid"),
                entry = null,
            )
        }
        val vaultRefusal = vaultGuard.check()
        if (vaultRefusal != null) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, vaultRefusal.failure, vaultRefusal.detail),
                entry = null,
            )
        }
        val safePermissions = permissions?.takeIf { value -> PERMISSION_PATTERN.matches(value) }
        val fileName = vaultFileName(sha256, at)
        // The metadata row is constructed before the first command so a migration can never leave a
        // moved binary without a vault entry.
        val entry = try {
            TitanVaultEntry(
                id = UUID.randomUUID().toString(),
                fileName = fileName,
                originalPath = sourcePath,
                sha256 = sha256,
                sizeBytes = sizeBytes,
                storedAtMillis = at,
                permissions = safePermissions,
            )
        } catch (_: IllegalArgumentException) {
            return QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.INVALID_TARGET, "metadata-invalid"),
                entry = null,
            )
        }
        return try {
            val prepare = shell.executeAll(TitanCommandFactory.prepareVault())
            if (prepare.any { result -> !result.ok }) {
                val failure = prepare.firstOrNull { result -> !result.ok }?.failure ?: TitanActionFailure.COMMAND_FAILED
                return QuarantineOutcome(
                    result = quarantineFailure(target, at, failure, "vault-prepare-failed"),
                    entry = null,
                )
            }
            val move = shell.execute(TitanCommandFactory.moveToVault(sourcePath, fileName))
            if (!move.ok) {
                return QuarantineOutcome(
                    result = quarantineFailure(target, at, move.failure ?: TitanActionFailure.COMMAND_FAILED, "vault-move-failed"),
                    entry = null,
                )
            }
            val chmod = shell.execute(TitanCommandFactory.chmodVault(fileName))
            val verified = chmod.ok && vaultListingContains(fileName)
            if (verified) {
                QuarantineOutcome(
                    result = TitanActionResult(
                        action = QUARANTINE_RESULT_ACTION,
                        target = target,
                        executedAtMillis = at,
                        ok = true,
                        verified = true,
                        failure = null,
                        detail = "tags=vault-move,vault-chmod verify=true",
                    ),
                    entry = entry,
                )
            } else {
                QuarantineOutcome(
                    result = quarantineFailure(
                        target = target,
                        at = at,
                        failure = chmod.failure ?: TitanActionFailure.VERIFICATION_FAILED,
                        detail = "tags=vault-chmod exit=${chmod.exitCode} verify=false",
                    ),
                    entry = entry,
                )
            }
        } catch (error: Throwable) {
            Log.w(TAG, "titan_quarantine_failed:${error.javaClass.simpleName}")
            QuarantineOutcome(
                result = quarantineFailure(target, at, TitanActionFailure.UNAVAILABLE, "engine-error"),
                entry = null,
            )
        }
    }

    // ------------------------------------------------------------------ command mapping

    private fun commandsFor(request: TitanActionRequest): List<TitanShellCommand> = when (request.action) {
        TitanContainmentAction.FREEZE_APP -> listOf(TitanCommandFactory.freezeApp(requirePackage(request)))
        TitanContainmentAction.RESTORE_APP -> listOf(TitanCommandFactory.restoreApp(requirePackage(request)))
        TitanContainmentAction.ISOLATE_NETWORK_UID -> listOf(TitanCommandFactory.isolateUid(requireUid(request)))
        TitanContainmentAction.RELEASE_NETWORK_UID -> listOf(TitanCommandFactory.releaseUid(requireUid(request)))
        TitanContainmentAction.KILL_PROCESS -> listOf(TitanCommandFactory.killProcess(requirePid(request)))
        TitanContainmentAction.CLOSE_ADB_PORT -> TitanCommandFactory.closeAdbTcp()
    }

    private fun requirePackage(request: TitanActionRequest): String =
        request.target.packageName ?: throw IllegalArgumentException("missing target package")

    private fun requireUid(request: TitanActionRequest): Int =
        request.target.uid ?: throw IllegalArgumentException("missing target uid")

    private fun requirePid(request: TitanActionRequest): Int =
        request.target.pid ?: throw IllegalArgumentException("missing target pid")

    // ------------------------------------------------------------------ effect verification

    private fun verifyEffect(request: TitanActionRequest): Boolean = try {
        when (request.action) {
            TitanContainmentAction.FREEZE_APP -> freezeVerified(requirePackage(request))
            TitanContainmentAction.RESTORE_APP -> restoreVerified(requirePackage(request))
            TitanContainmentAction.ISOLATE_NETWORK_UID -> isolateVerified(requireUid(request))
            TitanContainmentAction.RELEASE_NETWORK_UID -> releaseVerified(requireUid(request))
            TitanContainmentAction.KILL_PROCESS -> processGoneVerified(requirePid(request))
            TitanContainmentAction.CLOSE_ADB_PORT -> adbPortClosedVerified()
        }
    } catch (_: Throwable) {
        false
    }

    private fun freezeVerified(packageName: String): Boolean {
        val table = shell.readTable(TitanCommandFactory.listDisabledPackages()) ?: return false
        return table.lineSequence().any { line -> line.trim() == PACKAGE_LINE_PREFIX + packageName }
    }

    private fun restoreVerified(packageName: String): Boolean {
        val table = shell.readTable(TitanCommandFactory.listDisabledPackages()) ?: return false
        return table.lineSequence().none { line -> line.trim() == PACKAGE_LINE_PREFIX + packageName }
    }

    private fun isolateVerified(uid: Int): Boolean {
        val table = shell.readTable(TitanCommandFactory.listInputFilter()) ?: return false
        return containsUidRule(table, uid)
    }

    private fun releaseVerified(uid: Int): Boolean {
        val table = shell.readTable(TitanCommandFactory.listInputFilter()) ?: return false
        return !containsUidRule(table, uid)
    }

    /** Thin delegate to the F-03 hardened `/proc` absence probe in [TitanProcessProbe]. */
    private fun processGoneVerified(pid: Int): Boolean = processProbe.isGone(pid)

    private fun adbPortClosedVerified(): Boolean {
        val probe = shell.execute(TitanCommandFactory.readAdbTcpPort())
        if (!probe.ok || probe.timedOut) return false
        val value = probe.output.trim()
        return value.isEmpty() || value == ADB_TCP_DISABLED_VALUE
    }

    /** True when one iptables OUTPUT line carries the owner rule of [uid]. */
    private fun containsUidRule(table: String, uid: Int): Boolean {
        val token = uid.toString()
        val tokenPattern = Regex("(^|[\\s:])" + token + "(\\s|$)")
        return table.lineSequence().any { line ->
            line.contains("--uid-owner $token") ||
                (line.contains("UID match") && tokenPattern.containsMatchIn(line))
        }
    }

    private fun vaultListingContains(fileName: String): Boolean {
        val listing = shell.readTable(TitanCommandFactory.listDirectory(TitanFimPolicy.VAULT_PATH)) ?: return false
        return listing.lineSequence().any { line ->
            line.trim().endsWith(" $fileName") || line.trim() == fileName
        }
    }

    // ------------------------------------------------------------------ result helpers

    private fun quarantineFailure(
        target: TitanActionTarget,
        at: Long,
        failure: TitanActionFailure,
        detail: String,
    ): TitanActionResult = TitanActionResult(
        action = QUARANTINE_RESULT_ACTION,
        target = target,
        executedAtMillis = at,
        ok = false,
        verified = false,
        failure = failure,
        detail = detail.take(MAX_DETAIL_CHARS),
    )

    private fun commandDetail(
        commands: List<TitanShellCommand>,
        results: List<TitanShellResult>,
        verify: Boolean,
        failure: TitanActionFailure?,
    ): String {
        val tags = commands.take(MAX_DETAIL_TAGS).joinToString(",") { command -> command.auditTag }
        val exitCodes = results.take(MAX_DETAIL_TAGS).joinToString(",") { result -> result.exitCode.toString() }
        val rendered = "tags=$tags exit=$exitCodes verify=$verify fail=${failure?.name?.lowercase() ?: "none"}"
        return rendered.take(MAX_DETAIL_CHARS).replace('\n', ' ').replace('\r', ' ')
    }

    private fun vaultFileName(sha256: String, atMillis: Long): String {
        val unique = UUID.randomUUID().toString().replace("-", "").take(VAULT_NAME_RANDOM_CHARS)
        return sha256.take(VAULT_NAME_HASH_CHARS) + "-" + atMillis + "-" + unique + ".bin"
    }

    private fun isSelfTarget(request: TitanActionRequest): Boolean {
        val target = request.target
        return target.packageName == selfPackage ||
            target.uid == selfUid ||
            target.pid == android.os.Process.myPid()
    }

    private companion object {
        const val TAG = "GeDefenseTv"
        const val MAX_DETAIL_CHARS = 256
        const val MAX_DETAIL_TAGS = 4
        const val MAX_LABEL_CHARS = 96
        const val VAULT_NAME_HASH_CHARS = 12
        const val VAULT_NAME_RANDOM_CHARS = 8
        const val PACKAGE_LINE_PREFIX = "package:"
        const val ADB_TCP_DISABLED_VALUE = "-1"

        /**
         * Reusable reversible containment kind used to carry a vault audit result through the
         * existing evidence path. tv-core has no vault action in 0.3.0-alpha1; the audit detail and
         * the vault entry identify the real operation.
         */
        val QUARANTINE_RESULT_ACTION: TitanContainmentAction = TitanContainmentAction.FREEZE_APP

        val SHA256_PATTERN = Regex("[0-9a-f]{64}")
        val PERMISSION_PATTERN = Regex("[0-7]{3,4}")
    }
}
