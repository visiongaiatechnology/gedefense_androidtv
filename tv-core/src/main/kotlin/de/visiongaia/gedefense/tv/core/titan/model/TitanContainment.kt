package de.visiongaia.gedefense.tv.core.titan.model

import de.visiongaia.gedefense.tv.core.model.MessageRef

/**
 * Reversible containment actions.
 *
 * The product rule is absolute: Titan only ever applies actions that can be undone with the remote.
 * There is no "delete", no partition write and no unfiltered shell command in this enum.
 */
enum class TitanContainmentAction {
    FREEZE_APP,
    RESTORE_APP,
    ISOLATE_NETWORK_UID,
    RELEASE_NETWORK_UID,
    KILL_PROCESS,
    CLOSE_ADB_PORT,
    ;

    val isReversible: Boolean
        get() = this != CLOSE_ADB_PORT
}

/** Why an action was requested; persisted with the action result for the evidence trail. */
enum class TitanActionReason { USER_INITIATED, C2_SOCKET, UNATTRIBUTED_SOCKET, FIM_TAMPER, ADB_EXPOSURE }

/** Stable failure codes surfaced by UI and report. */
enum class TitanActionFailure {
    NOT_AUTHORIZED,
    NOT_SUPPORTED,
    INVALID_TARGET,
    PROTECTED_TARGET,
    RATE_LIMITED,
    LIMIT_REACHED,
    COMMAND_FAILED,
    VERIFICATION_FAILED,
    UNAVAILABLE,
}

/**
 * Validated address of a containment action.
 *
 * At least one identifier must be present, but which one is required depends on the action and is
 * enforced by the command factory and the [TitanContainmentPolicy].
 */
data class TitanActionTarget(
    val packageName: String? = null,
    val uid: Int? = null,
    val pid: Int? = null,
    val label: String? = null,
) {
    init {
        require(packageName == null || (packageName.length <= 256 && packageName.matches(PACKAGE_PATTERN))) {
            "invalid action package"
        }
        require(uid == null || uid in 1..MAX_UID) { "invalid action uid" }
        require(pid == null || pid in 1..MAX_PID) { "invalid action pid" }
        require(label == null || label.length <= 96) { "action label too long" }
    }

    /** Compact stable identifier for evidence and vault metadata. */
    fun identity(): String = packageName ?: uid?.let { "uid:$it" } ?: pid?.let { "pid:$it" } ?: "device"

    companion object {
        const val MAX_UID = 2_000_000_000
        const val MAX_PID = 4_194_304
        // Single-segment platform packages such as "android" are valid targets for policy checks.
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){0,15}")
    }
}

/** One requested containment, validated but not yet executed. */
data class TitanActionRequest(
    val action: TitanContainmentAction,
    val target: TitanActionTarget,
    val reason: TitanActionReason,
    val requestedAtMillis: Long,
) {
    init {
        require(requestedAtMillis > 0L) { "invalid action timestamp" }
    }
}

/** Result of one executed (or refused) containment action. */
data class TitanActionResult(
    val action: TitanContainmentAction,
    val target: TitanActionTarget,
    val executedAtMillis: Long,
    val ok: Boolean,
    val verified: Boolean,
    val failure: TitanActionFailure? = null,
    /** Secret-free audit detail (command tag, exit code, verification result). */
    val detail: String? = null,
) {
    init {
        require(executedAtMillis > 0L) { "invalid action result timestamp" }
        require(detail == null || detail.length <= 256) { "action detail too long" }
        require(detail == null || detail.none { it == '\n' || it == '\r' }) { "action detail must be one line" }
        require(ok || failure != null) { "failed action requires a failure code" }
        require(failure == null || !ok) { "successful action must not carry a failure code" }
    }
}

/** Decision of the containment policy before any command is executed. */
data class TitanActionDecision(
    val allowed: Boolean,
    val failure: TitanActionFailure?,
    val reasonKey: MessageRef,
    val requiredCapability: TitanCapability?,
) {
    init {
        require(allowed || failure != null) { "refused decision requires a failure code" }
        require(allowed == (failure == null)) { "inconsistent decision" }
    }
}

/**
 * Metadata of one quarantined object.
 *
 * The metadata row itself is what the vault shows; binaries are moved out of executable locations
 * and lose execute permission. Its integrity is covered by the app's local vault MAC chain, not by
 * the file mode alone.
 */
data class TitanVaultEntry(
    val id: String,
    val fileName: String,
    val originalPath: String,
    val sha256: String,
    val sizeBytes: Long,
    val storedAtMillis: Long,
    val permissions: String?,
) {
    init {
        require(id.matches(UUID_PATTERN)) { "invalid vault id" }
        require(fileName.length in 1..128 && fileName.matches(FILE_PATTERN)) { "invalid vault file name" }
        require(TitanFimPolicy.isSafeAbsolutePath(originalPath)) { "invalid vault source path" }
        require(sha256.matches(Regex("[0-9a-f]{64}"))) { "invalid vault hash" }
        require(sizeBytes >= 0L) { "negative vault size" }
        require(storedAtMillis > 0L) { "invalid vault timestamp" }
        require(permissions == null || permissions.matches(Regex("[0-7]{3,4}"))) { "invalid vault permissions" }
    }

    companion object {
        const val UUID_PATTERN_TEXT = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
        private val UUID_PATTERN = Regex(UUID_PATTERN_TEXT)
        private val FILE_PATTERN = Regex("[A-Za-z0-9._-]{1,128}")
    }
}

/** Stable MessageRef keys of containment decisions (mapped to localized catalog strings). */
object TitanDecisionKeys {
    const val ALLOWED = "titan.decision.allowed"
    const val NOT_AUTHORIZED = "titan.decision.notauthorized"
    const val PROTECTED = "titan.decision.protected"
    const val INVALID_TARGET = "titan.decision.invalidtarget"
    const val RATE_LIMITED = "titan.decision.ratelimited"
    const val LIMIT_REACHED = "titan.decision.limitreached"
}
