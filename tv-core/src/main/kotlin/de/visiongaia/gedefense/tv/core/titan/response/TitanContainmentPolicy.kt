package de.visiongaia.gedefense.tv.core.titan.response

import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionDecision
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionRequest
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanDecisionKeys

/**
 * Fail-safe containment gate.
 *
 * Nothing is executed before this policy returned [TitanActionDecision.allowed]: the gate checks the
 * confirmed capability set, target shape, protected system packages/PIDs, the number of simultaneous
 * containments and a per-window action budget. This is the "no brick" layer: the user can always
 * restore a frozen app, and critical system components are unreachable by design.
 *
 * The policy is stateful only for the bounded rate-limit window; it is safe to call from one
 * controller thread (methods are synchronized).
 */
class TitanContainmentPolicy(
    private val selfPackage: String,
    private val selfUid: Int? = null,
    private val selfPid: Int? = null,
    protectedPackages: Set<String> = DEFAULT_PROTECTED_PACKAGES,
    private val maxActionsPerWindow: Int = DEFAULT_MAX_ACTIONS,
    private val windowMillis: Long = DEFAULT_WINDOW_MILLIS,
    private val maxActiveContainments: Int = DEFAULT_MAX_ACTIVE,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val protectedPackages: Set<String> = protectedPackages + selfPackage
    private val actionTimes = ArrayDeque<Long>()

    init {
        require(selfPackage.matches(PACKAGE_PATTERN)) { "invalid self package" }
        require(selfUid == null || selfUid in 1..TitanActionTargetLimits.MAX_UID) { "invalid self uid" }
        require(selfPid == null || selfPid in 1..TitanActionTargetLimits.MAX_PID) { "invalid self pid" }
        require(protectedPackages.all { it.length <= 256 && it.matches(PACKAGE_PATTERN) }) { "invalid protected package" }
        require(maxActionsPerWindow in 1..64) { "invalid action budget" }
        require(windowMillis in 1_000L..600_000L) { "invalid action window" }
        require(maxActiveContainments in 1..64) { "invalid active containment limit" }
    }

    /** Capability required for an action; also used by the UI to grey out unavailable controls. */
    fun requiredCapability(action: TitanContainmentAction): TitanCapability = when (action) {
        TitanContainmentAction.FREEZE_APP, TitanContainmentAction.RESTORE_APP -> TitanCapability.APP_FREEZE
        TitanContainmentAction.ISOLATE_NETWORK_UID,
        TitanContainmentAction.RELEASE_NETWORK_UID,
        -> TitanCapability.NETWORK_QUARANTINE

        TitanContainmentAction.KILL_PROCESS -> TitanCapability.PROCESS_KILL
        TitanContainmentAction.CLOSE_ADB_PORT -> TitanCapability.ADB_LOCKDOWN
    }

    @Synchronized
    fun evaluate(
        capabilities: Set<TitanCapability>,
        request: TitanActionRequest,
        activeContainments: Int,
    ): TitanActionDecision {
        val capability = requiredCapability(request.action)
        val target = request.target
        when (request.action) {
            TitanContainmentAction.FREEZE_APP, TitanContainmentAction.RESTORE_APP -> {
                if (target.packageName == null) return refuse(TitanActionFailure.INVALID_TARGET, TitanDecisionKeys.INVALID_TARGET, capability)
            }

            TitanContainmentAction.ISOLATE_NETWORK_UID, TitanContainmentAction.RELEASE_NETWORK_UID -> {
                val uid = target.uid
                if (uid == null || uid < TitanActionTargetLimits.MIN_THIRD_PARTY_UID) {
                    return refuse(TitanActionFailure.INVALID_TARGET, TitanDecisionKeys.INVALID_TARGET, capability)
                }
            }

            TitanContainmentAction.KILL_PROCESS -> {
                val pid = target.pid
                if (pid == null || pid < 2) return refuse(TitanActionFailure.INVALID_TARGET, TitanDecisionKeys.INVALID_TARGET, capability)
            }

            TitanContainmentAction.CLOSE_ADB_PORT -> Unit
        }
        if (capability !in capabilities) {
            return refuse(TitanActionFailure.NOT_AUTHORIZED, TitanDecisionKeys.NOT_AUTHORIZED, capability)
        }
        val protected = when (request.action) {
            TitanContainmentAction.FREEZE_APP, TitanContainmentAction.RESTORE_APP ->
                target.packageName != null && target.packageName in protectedPackages

            TitanContainmentAction.ISOLATE_NETWORK_UID, TitanContainmentAction.RELEASE_NETWORK_UID ->
                target.uid != null && (target.uid < TitanActionTargetLimits.MIN_THIRD_PARTY_UID || target.uid == selfUid)

            TitanContainmentAction.KILL_PROCESS -> target.pid != null && (target.pid == 1 || target.pid == selfPid)
            TitanContainmentAction.CLOSE_ADB_PORT -> false
        }
        if (protected) return refuse(TitanActionFailure.PROTECTED_TARGET, TitanDecisionKeys.PROTECTED, capability)
        // Recovery actions must always stay possible: an active/rate limit that blocks RESTORE or
        // RELEASE could leave a frozen app or a blocked UID unreachable without adb. Only forward
        // containment actions consume the budget.
        val recovery = request.action == TitanContainmentAction.RESTORE_APP ||
            request.action == TitanContainmentAction.RELEASE_NETWORK_UID
        if (!recovery) {
            if (activeContainments >= maxActiveContainments) {
                return refuse(TitanActionFailure.LIMIT_REACHED, TitanDecisionKeys.LIMIT_REACHED, capability)
            }
            prune(clock())
            if (actionTimes.size >= maxActionsPerWindow) {
                return refuse(TitanActionFailure.RATE_LIMITED, TitanDecisionKeys.RATE_LIMITED, capability)
            }
        }
        return TitanActionDecision(
            allowed = true,
            failure = null,
            reasonKey = MessageRef(TitanDecisionKeys.ALLOWED, listOf(request.action.name.lowercase())),
            requiredCapability = capability,
        )
    }

    /** Must be called once for every executed (or attempted) action, including failed ones. */
    @Synchronized
    fun recordExecution() {
        val now = clock()
        actionTimes.addLast(now)
        prune(now)
        while (actionTimes.size > maxActionsPerWindow * MAX_HISTORY_FACTOR) actionTimes.removeFirst()
    }

    @Synchronized
    fun recentActionCount(): Int {
        prune(clock())
        return actionTimes.size
    }

    fun protectedPackageNames(): Set<String> = protectedPackages

    fun canFreeze(packageName: String): Boolean =
        packageName.matches(PACKAGE_PATTERN) && packageName !in protectedPackages

    private fun prune(now: Long) {
        val cutoff = now - windowMillis
        while (actionTimes.isNotEmpty() && actionTimes.first() <= cutoff) actionTimes.removeFirst()
    }

    private fun refuse(
        failure: TitanActionFailure,
        reasonKey: String,
        capability: TitanCapability?,
    ): TitanActionDecision = TitanActionDecision(
        allowed = false,
        failure = failure,
        reasonKey = MessageRef(reasonKey),
        requiredCapability = capability,
    )

    companion object {
        const val DEFAULT_MAX_ACTIONS = 8
        const val DEFAULT_WINDOW_MILLIS = 60_000L
        const val DEFAULT_MAX_ACTIVE = 16
        private const val MAX_HISTORY_FACTOR = 4
        // Single-segment platform packages such as "android" are valid protected targets.
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){0,15}")

        /**
         * System-critical packages that must never be frozen by Titan. Freezing any of them can make
         * the TV unusable (black screen, no settings, no package installer) and could not always be
         * restored by the user without adb.
         */
        val DEFAULT_PROTECTED_PACKAGES: Set<String> = setOf(
            "android",
            "com.android.systemui",
            "com.android.settings",
            "com.android.tv.settings",
            "com.android.shell",
            "com.android.packageinstaller",
            "com.google.android.packageinstaller",
            "com.android.vending",
            "com.google.android.gms",
            "com.google.android.gsf",
            "com.android.providers.settings",
            "com.android.providers.tv",
            "com.android.tv",
            "com.google.android.tvlauncher",
            "com.google.android.apps.tv.launcherx",
            "com.google.android.leanbacklauncher",
            "com.android.inputmethod.latin",
            "com.google.android.inputmethod.latin",
        )
    }
}
