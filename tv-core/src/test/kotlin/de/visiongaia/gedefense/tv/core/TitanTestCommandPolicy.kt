package de.visiongaia.gedefense.tv.core

import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.mobile.core.ThreatRecord
import de.visiongaia.gedefense.tv.core.model.*
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.TitanStatusComposer
import de.visiongaia.gedefense.tv.core.titan.events.TitanEventFactory
import de.visiongaia.gedefense.tv.core.titan.fim.FimComparison
import de.visiongaia.gedefense.tv.core.titan.fim.FimEngine
import de.visiongaia.gedefense.tv.core.titan.model.*
import de.visiongaia.gedefense.tv.core.titan.proc.ProcNetParser
import de.visiongaia.gedefense.tv.core.titan.proc.SocketProvenanceEngine
import de.visiongaia.gedefense.tv.core.titan.response.*
import de.visiongaia.gedefense.tv.core.titan.witness.TitanWitnessCheckpointFactory
import de.visiongaia.gedefense.tv.core.titan.witness.TitanWitnessCheckpointFactory.LedgerRow
import java.io.File
import javax.crypto.SecretKey
import kotlin.system.exitProcess

// --- command factory tests ---------------------------------------------------------------------

private val safeArgument = Regex("[A-Za-z0-9_./:@+=,%-]+")

private fun checkCommand(command: TitanShellCommand, program: String, arguments: List<String>, tag: String) {
    titanCheckEquals(command.program, program, "$tag program")
    titanCheckEquals(command.arguments, arguments, "$tag arguments")
    titanCheckEquals(command.requiresRoot, true, "$tag requires root")
    titanCheckEquals(command.auditTag, tag, "$tag audit tag")
    titanCheckTrue(command.program in TitanShellCommand.ALLOWED_PROGRAMS, "$tag allowlisted program")
    titanCheckTrue(command.arguments.all { argument -> argument.length in 1..512 && safeArgument.matches(argument) }, "$tag safe arguments")
    titanCheckEquals(command.shellLine(), (listOf(program) + arguments).joinToString(" "), "$tag shell line")
    titanCheckEquals(command.auditLine(), "$tag:$program(${arguments.size})", "$tag audit line")
    titanCheckTrue(command.shellLine().none { character -> character in ";&|$`'\"<>\n\r" }, "$tag no shell metacharacters")
}

private fun testCommandCommands() {
    checkCommand(TitanCommandFactory.freezeApp("com.example.app"), "pm", listOf("disable-user", "--user", "0", "com.example.app"), "freeze-app")
    checkCommand(TitanCommandFactory.restoreApp("com.example.app"), "pm", listOf("enable", "com.example.app"), "restore-app")
    checkCommand(TitanCommandFactory.forceStopApp("com.example.app"), "am", listOf("force-stop", "com.example.app"), "force-stop-app")
    checkCommand(
        TitanCommandFactory.isolateUid(10_050), "iptables",
        listOf("-w", "-I", "OUTPUT", "1", "-m", "owner", "--uid-owner", "10050", "-j", "DROP"), "isolate-uid",
    )
    checkCommand(
        TitanCommandFactory.releaseUid(10_050), "iptables",
        listOf("-w", "-D", "OUTPUT", "-m", "owner", "--uid-owner", "10050", "-j", "DROP"), "release-uid",
    )
    checkCommand(TitanCommandFactory.killProcess(4_242), "kill", listOf("-9", "4242"), "kill-process")
    checkCommand(TitanCommandFactory.probeProcess(4_242), "kill", listOf("-0", "4242"), "verify-process")
    checkCommand(TitanCommandFactory.closeAdbTcp()[0], "setprop", listOf("service.adb.tcp.port", "-1"), "adb-port-off")
    checkCommand(TitanCommandFactory.closeAdbTcp()[1], "stop", listOf("adbd"), "adbd-stop")
    titanCheckEquals(TitanCommandFactory.closeAdbTcp().size, 2, "ADB lockdown command pair")
    checkCommand(TitanCommandFactory.prepareVault()[0], "mkdir", listOf("-p", "--", TITAN_VAULT), "vault-mkdir")
    checkCommand(TitanCommandFactory.prepareVault()[1], "chmod", listOf("700", "--", TITAN_VAULT), "vault-chmod")
    checkCommand(
        TitanCommandFactory.moveToVault("$TITAN_TMP_ROOT/evil.sh", "evil.sh"), "mv",
        listOf("--", "$TITAN_TMP_ROOT/evil.sh", "$TITAN_VAULT/evil.sh"), "vault-move",
    )
    checkCommand(TitanCommandFactory.chmodVault("evil.sh"), "chmod", listOf("000", "--", "$TITAN_VAULT/evil.sh"), "vault-chmod-file")
    checkCommand(TitanCommandFactory.listDisabledPackages(), "cmd", listOf("package", "list", "packages", "-d"), "verify-disabled")
    checkCommand(TitanCommandFactory.listInputFilter(), "iptables", listOf("-w", "-L", "OUTPUT", "-n", "-v"), "verify-iptables")
    checkCommand(TitanCommandFactory.readAdbTcpPort(), "getprop", listOf("service.adb.tcp.port"), "verify-adb-port")
    checkCommand(TitanCommandFactory.probeRootIdentity(), "id", emptyList(), "probe-root")
    checkCommand(
        TitanCommandFactory.listWatchRoot(TITAN_TMP_ROOT, recursive = true, maxDepth = 2), "find",
        listOf(TITAN_TMP_ROOT, "-maxdepth", "2", "-type", "f", "-print"), "fim-find",
    )
    checkCommand(
        TitanCommandFactory.listWatchRoot("/system/bin", recursive = false, maxDepth = 1), "find",
        listOf("/system/bin", "-maxdepth", "1", "-mindepth", "1", "-type", "f", "-print"), "fim-find",
    )
    checkCommand(TitanCommandFactory.statFile("$TITAN_TMP_ROOT/a.sh"), "stat", listOf("-c", "%a:%s:%Y", "--", "$TITAN_TMP_ROOT/a.sh"), "fim-stat")
    checkCommand(TitanCommandFactory.sha256File("$TITAN_TMP_ROOT/a.sh"), "sha256sum", listOf("--", "$TITAN_TMP_ROOT/a.sh"), "fim-sha256")
    checkCommand(TitanCommandFactory.readProcTable("/proc/net/tcp"), "cat", listOf("/proc/net/tcp"), "read-proc")
    checkCommand(TitanCommandFactory.listDirectory("/proc/1/fd"), "ls", listOf("-ln", "--", "/proc/1/fd"), "list-dir")
    checkCommand(TitanCommandFactory.readProcessStatus(1), "cat", listOf("/proc/1/status"), "read-proc-status")
    val allowlist = TitanShellCommand.ALLOWED_PROGRAMS
    val expectedPrograms = setOf(
        "pm", "am", "iptables", "setprop", "stop", "kill", "chmod", "mv", "mkdir",
        "cmd", "getprop", "id", "find", "stat", "sha256sum", "cat", "ls",
    )
    titanCheckEquals(allowlist, expectedPrograms, "allowed program allowlist exactly minimal")
    expectedPrograms.forEach { program ->
        titanCheckTrue(program in allowlist, "allowlisted $program")
    }
    listOf("sh", "bash", "rm", "dd", "mount", "reboot", "su", "rmdir", "truncate", "wipe").forEach { program ->
        titanCheckTrue(program !in allowlist, "denied $program")
    }
    val allCommands = listOf(
        TitanCommandFactory.freezeApp("com.example.app"),
        TitanCommandFactory.restoreApp("com.example.app"),
        TitanCommandFactory.isolateUid(10_050),
        TitanCommandFactory.releaseUid(10_050),
        TitanCommandFactory.killProcess(4_242),
        TitanCommandFactory.moveToVault("$TITAN_TMP_ROOT/evil.sh", "evil.sh"),
    )
    allCommands.forEach { command ->
        titanCheckTrue(command.requiresRoot, "command requires confirmed root channel")
        titanCheckTrue(command.arguments.none { argument -> argument.contains(" ") }, "no whitespace injected into arguments")
    }
    titanCheckThrows<IllegalArgumentException>("unknown program rejected") {
        TitanShellCommand("rm", listOf("-rf", "/"), true, "destructive")
    }
    titanCheckThrows<IllegalArgumentException>("unsafe argument rejected") {
        TitanShellCommand("pm", listOf("enable; reboot"), true, "unsafe")
    }
    titanCheckThrows<IllegalArgumentException>("short audit tag rejected") {
        TitanShellCommand("pm", listOf("enable"), true, "x")
    }
    titanCheckThrows<IllegalArgumentException>("too many arguments rejected") {
        TitanShellCommand("pm", List(17) { index -> "arg$index" }, true, "too-many")
    }
}

private fun testCommandRejections() {
    val unsafePackages = listOf(
        "com.example;rm", "com.example rm", "com/example", "com..example", ".com.example",
        "com.example.", "$(id)", "com.example\n", "a".repeat(300), "", "com.example|cat", "../system",
    )
    unsafePackages.forEach { packageName ->
        titanCheckThrows<IllegalArgumentException>("freeze rejects '$packageName'") { TitanCommandFactory.freezeApp(packageName) }
    }
    listOf("com.example;rm", "../x", "$(id)").forEach { packageName ->
        titanCheckThrows<IllegalArgumentException>("restore rejects '$packageName'") { TitanCommandFactory.restoreApp(packageName) }
        titanCheckThrows<IllegalArgumentException>("force-stop rejects '$packageName'") { TitanCommandFactory.forceStopApp(packageName) }
    }
    listOf(0, 1, 9_999, -1, Int.MAX_VALUE).forEach { uid ->
        titanCheckThrows<IllegalArgumentException>("isolate rejects uid $uid") { TitanCommandFactory.isolateUid(uid) }
        titanCheckThrows<IllegalArgumentException>("release rejects uid $uid") { TitanCommandFactory.releaseUid(uid) }
    }
    listOf(10_000, 10_050, 100_000).forEach { uid ->
        titanCheckTrue(TitanCommandFactory.isolateUid(uid).shellLine().contains(uid.toString()), "isolate accepts uid $uid")
    }
    listOf(0, 1, -5, TitanActionTargetLimits.MAX_PID + 1).forEach { pid ->
        titanCheckThrows<IllegalArgumentException>("kill rejects pid $pid") { TitanCommandFactory.killProcess(pid) }
        titanCheckThrows<IllegalArgumentException>("probe rejects pid $pid") { TitanCommandFactory.probeProcess(pid) }
    }
    listOf(2, 4_242, TitanActionTargetLimits.MAX_PID).forEach { pid ->
        titanCheckTrue(TitanCommandFactory.killProcess(pid).shellLine().contains(pid.toString()), "kill accepts pid $pid")
    }
    titanCheckThrows<IllegalArgumentException>("vault source outside watch roots rejected") {
        TitanCommandFactory.moveToVault("/etc/passwd", "passwd")
    }
    titanCheckThrows<IllegalArgumentException>("vault source traversal rejected") {
        TitanCommandFactory.moveToVault("$TITAN_TMP_ROOT/../system/x", "x")
    }
    listOf("../evil", "evil;sh", "", "a".repeat(129), "evil sh").forEach { fileName ->
        titanCheckThrows<IllegalArgumentException>("vault file name '$fileName' rejected") {
            TitanCommandFactory.moveToVault("$TITAN_TMP_ROOT/evil.sh", fileName)
        }
        titanCheckThrows<IllegalArgumentException>("chmod vault file '$fileName' rejected") { TitanCommandFactory.chmodVault(fileName) }
    }
    titanCheckThrows<IllegalArgumentException>("find root outside policy rejected") {
        TitanCommandFactory.listWatchRoot("/etc", recursive = true, maxDepth = 1)
    }
    listOf(-1, FimWatchRoot.MAX_DEPTH + 1).forEach { depth ->
        titanCheckThrows<IllegalArgumentException>("find depth $depth rejected") {
            TitanCommandFactory.listWatchRoot(TITAN_TMP_ROOT, recursive = true, maxDepth = depth)
        }
    }
    titanCheckThrows<IllegalArgumentException>("stat outside watch roots rejected") { TitanCommandFactory.statFile("/etc/passwd") }
    titanCheckThrows<IllegalArgumentException>("sha256 outside watch roots rejected") { TitanCommandFactory.sha256File("/etc/passwd") }
    titanCheckThrows<IllegalArgumentException>("proc read outside procfs rejected") { TitanCommandFactory.readProcTable("/etc/passwd") }
    titanCheckThrows<IllegalArgumentException>("proc traversal rejected") { TitanCommandFactory.readProcTable("/proc/../etc/passwd") }
    titanCheckTrue(TitanCommandFactory.readProcTable("/sys/class/net").program == "cat", "sys read allowed")
    titanCheckThrows<IllegalArgumentException>("directory listing outside roots rejected") { TitanCommandFactory.listDirectory("/etc") }
    titanCheckThrows<IllegalArgumentException>("directory listing traversal rejected") { TitanCommandFactory.listDirectory("/data/../etc") }
    listOf(0, -1, TitanActionTargetLimits.MAX_PID + 1).forEach { pid ->
        titanCheckThrows<IllegalArgumentException>("process status pid $pid rejected") { TitanCommandFactory.readProcessStatus(pid) }
    }
}

// --- containment policy tests ------------------------------------------------------------------


private fun testPolicyActions() {
    val policy = TitanContainmentPolicy(selfPackage = "de.visiongaia.gedefense.tv", selfUid = 10_100, selfPid = 2_000)
    val capabilities = allCapabilities()
    TitanContainmentAction.values().forEach { action ->
        val decision = policy.evaluate(capabilities, actionRequest(action), activeContainments = 0)
        titanCheckEquals(decision.allowed, true, "$action allowed with capability")
        titanCheckEquals(decision.failure, null, "$action no failure")
        titanCheckEquals(decision.requiredCapability, expectedCapability(action), "$action required capability")
        titanCheckEquals(decision.reasonKey, MessageRef(TitanDecisionKeys.ALLOWED, listOf(action.name.lowercase())), "$action allowed reason")
    }
    TitanContainmentAction.values().forEach { action ->
        val refused = policy.evaluate(emptySet(), actionRequest(action), activeContainments = 0)
        titanCheckEquals(refused.allowed, false, "$action refused without capability")
        titanCheckEquals(refused.failure, TitanActionFailure.NOT_AUTHORIZED, "$action not authorized")
        titanCheckEquals(refused.reasonKey, MessageRef(TitanDecisionKeys.NOT_AUTHORIZED), "$action not authorized reason")
        titanCheckTrue(refused.requiredCapability != null, "$action refusal names capability")
    }
    titanCheckEquals(
        TitanActionTarget(packageName = "com.example.app").identity(),
        "com.example.app",
        "package target identity",
    )
    titanCheckEquals(TitanActionTarget(uid = 10_050).identity(), "uid:10050", "uid target identity")
    titanCheckEquals(TitanActionTarget(pid = 4_242).identity(), "pid:4242", "pid target identity")
    titanCheckEquals(TitanActionTarget().identity(), "device", "empty target identity")
    titanCheckTrue(policy.protectedPackageNames().contains("de.visiongaia.gedefense.tv"), "self package protected")
    titanCheckTrue(policy.protectedPackageNames().contains("com.android.systemui"), "system UI protected")
    titanCheckEquals(policy.recentActionCount(), 0, "policy starts without actions")
}

private fun testPolicyLimits() {
    val clock = FakeClock()
    fun policy(
        maxActions: Int = 8,
        window: Long = 60_000L,
        maxActive: Int = 16,
    ): TitanContainmentPolicy = TitanContainmentPolicy(
        selfPackage = "de.visiongaia.gedefense.tv",
        selfUid = 10_100,
        selfPid = 2_000,
        maxActionsPerWindow = maxActions,
        windowMillis = window,
        maxActiveContainments = maxActive,
        clock = clock::read,
    )
    val capabilities = allCapabilities()
    val policy = policy()
    TitanContainmentPolicy.DEFAULT_PROTECTED_PACKAGES.forEach { packageName ->
        titanCheckEquals(policy.canFreeze(packageName), false, "protected $packageName cannot freeze")
        val decision = policy.evaluate(
            capabilities, actionRequest(TitanContainmentAction.FREEZE_APP, TitanActionTarget(packageName = packageName)), 0,
        )
        titanCheckEquals(decision.allowed, false, "protected $packageName refused")
        titanCheckEquals(decision.failure, TitanActionFailure.PROTECTED_TARGET, "protected $packageName failure")
    }
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP, TitanActionTarget(packageName = "de.visiongaia.gedefense.tv")), 0).failure,
        TitanActionFailure.PROTECTED_TARGET,
        "own package protected",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP, TitanActionTarget()), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "freeze needs package",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.RESTORE_APP, TitanActionTarget()), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "restore needs package",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.ISOLATE_NETWORK_UID, TitanActionTarget()), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "isolate needs uid",
    )
    titanCheckThrows<IllegalArgumentException>("uid 0 is not a representable target") {
        TitanActionTarget(uid = 0)
    }
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.ISOLATE_NETWORK_UID, TitanActionTarget(uid = 9_999)), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "uid 9999 invalid target",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.KILL_PROCESS, TitanActionTarget()), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "kill needs pid",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.KILL_PROCESS, TitanActionTarget(pid = 1)), 0).failure,
        TitanActionFailure.INVALID_TARGET,
        "pid 1 invalid target",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.ISOLATE_NETWORK_UID, TitanActionTarget(uid = 10_100)), 0).failure,
        TitanActionFailure.PROTECTED_TARGET,
        "own uid protected",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.KILL_PROCESS, TitanActionTarget(pid = 2_000)), 0).failure,
        TitanActionFailure.PROTECTED_TARGET,
        "own pid protected",
    )
    titanCheckEquals(
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), activeContainments = 16).failure,
        TitanActionFailure.LIMIT_REACHED,
        "active containment limit",
    )
    titanCheckEquals(
        policy(maxActive = 2).evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), activeContainments = 1).allowed,
        true,
        "below active limit allowed",
    )
    titanCheckEquals(policy.canFreeze("com.example.app"), true, "regular app can freeze")
    titanCheckEquals(policy.canFreeze("bad package"), false, "invalid package cannot freeze")
    val ratePolicy = policy(maxActions = 3)
    repeat(3) {
        titanCheckEquals(
            ratePolicy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 0).allowed,
            true,
            "action $it within rate window",
        )
        ratePolicy.recordExecution()
    }
    titanCheckEquals(ratePolicy.recentActionCount(), 3, "rate window count")
    titanCheckEquals(
        ratePolicy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 0).failure,
        TitanActionFailure.RATE_LIMITED,
        "rate limit enforced",
    )
    clock.now += 60_001L
    titanCheckEquals(ratePolicy.recentActionCount(), 0, "rate window pruned")
    titanCheckEquals(
        ratePolicy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 0).allowed,
        true,
        "allowed after window",
    )
    // Recovery must never be blocked: RESTORE_APP and RELEASE_NETWORK_UID are exempt from the active
    // and rate limits, while forward containment stays gated.
    val recoveryPolicy = policy(maxActions = 3)
    repeat(3) { recoveryPolicy.recordExecution() }
    titanCheckEquals(recoveryPolicy.recentActionCount(), 3, "recovery fixture rate window exhausted")
    titanCheckEquals(
        recoveryPolicy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 16).failure,
        TitanActionFailure.LIMIT_REACHED,
        "freeze refused when active limit reached",
    )
    titanCheckEquals(
        recoveryPolicy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 0).failure,
        TitanActionFailure.RATE_LIMITED,
        "freeze refused when rate window exhausted",
    )
    fun protectedRecoveryTarget(action: TitanContainmentAction): TitanActionTarget = when (action) {
        TitanContainmentAction.RESTORE_APP -> TitanActionTarget(packageName = "com.android.settings")
        else -> TitanActionTarget(uid = 10_100)
    }
    listOf(TitanContainmentAction.RESTORE_APP, TitanContainmentAction.RELEASE_NETWORK_UID).forEach { action ->
        val decision = recoveryPolicy.evaluate(capabilities, actionRequest(action), 16)
        titanCheckEquals(decision.allowed, true, "recovery $action allowed with exhausted active/rate limits")
        titanCheckEquals(decision.failure, null, "recovery $action has no failure")
        titanCheckEquals(decision.requiredCapability, expectedCapability(action), "recovery $action capability")
        titanCheckEquals(
            recoveryPolicy.evaluate(emptySet(), actionRequest(action), 16).failure,
            TitanActionFailure.NOT_AUTHORIZED,
            "recovery $action still capability-gated",
        )
        titanCheckEquals(
            recoveryPolicy.evaluate(capabilities, actionRequest(action, protectedRecoveryTarget(action)), 16).failure,
            TitanActionFailure.PROTECTED_TARGET,
            "recovery $action still refuses protected targets",
        )
    }
    val refusedDecisions = listOf(
        policy.evaluate(emptySet(), actionRequest(TitanContainmentAction.FREEZE_APP), 0),
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP, TitanActionTarget(packageName = "com.android.settings")), 0),
        policy.evaluate(capabilities, actionRequest(TitanContainmentAction.FREEZE_APP), 16),
    )
    refusedDecisions.forEach { decision ->
        titanCheckEquals(decision.allowed, false, "refused decision not allowed")
        titanCheckTrue(decision.failure != null, "refused decision carries failure")
        titanCheckEquals(decision.allowed, decision.failure == null, "decision consistency")
        titanCheckEquals(decision.reasonKey.key.startsWith("titan.decision."), true, "refusal reason key namespace")
    }
    titanCheckThrows<IllegalArgumentException>("invalid self package rejected") {
        TitanContainmentPolicy(selfPackage = "bad package")
    }
    titanCheckThrows<IllegalArgumentException>("invalid self uid rejected") { TitanContainmentPolicy(selfPackage = "a.b", selfUid = 0) }
    titanCheckThrows<IllegalArgumentException>("invalid self pid rejected") { TitanContainmentPolicy(selfPackage = "a.b", selfPid = 0) }
    titanCheckThrows<IllegalArgumentException>("invalid protected package rejected") {
        TitanContainmentPolicy(selfPackage = "a.b", protectedPackages = setOf("bad package"))
    }
    titanCheckThrows<IllegalArgumentException>("invalid action budget rejected") { TitanContainmentPolicy(selfPackage = "a.b", maxActionsPerWindow = 0) }
    titanCheckThrows<IllegalArgumentException>("invalid window rejected") { TitanContainmentPolicy(selfPackage = "a.b", windowMillis = 999L) }
    titanCheckThrows<IllegalArgumentException>("invalid active limit rejected") {
        TitanContainmentPolicy(selfPackage = "a.b", maxActiveContainments = 65)
    }
}


internal fun registerCommandPolicyTests() {
    titanTest("command: allowlist, arguments, quoting", ::testCommandCommands)
    titanTest("command: injection and target rejection", ::testCommandRejections)
    titanTest("policy: allow/refuse per action", ::testPolicyActions)
    titanTest("policy: protected targets, limits, rate", ::testPolicyLimits)
}
