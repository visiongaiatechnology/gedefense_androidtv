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

// --- capability matrix + status composer tests -------------------------------------------------

private fun rootPrivilege(): TitanPrivilegeSnapshot = TitanPrivilegeSnapshot(
    level = TitanPrivilegeLevel.ROOT,
    rootKind = TitanRootKind.MANAGED,
    rootShellConfirmed = true,
    checkedAtMillis = TITAN_NOW,
    notes = listOf(MessageRef(TitanTextKeys.NOTE_SELINUX_PERMISSIVE)),
)

private fun testMatrixComposer() {
    val expectedTheory = mapOf(
        TitanPrivilegeLevel.STANDARD to emptySet<TitanCapability>(),
        TitanPrivilegeLevel.SHIZUKU to setOf(TitanCapability.SOCKET_PROVENANCE, TitanCapability.APP_FREEZE),
        TitanPrivilegeLevel.ROOT to allCapabilities(),
    )
    expectedTheory.forEach { (level, expected) ->
        titanCheckEquals(TitanCapabilityMatrix.theoreticalCapabilities(level), expected, "theoretical capabilities $level")
    }
    titanCheckEquals(TitanCapabilityMatrix.theoreticalVisibility(TitanPrivilegeLevel.STANDARD), DataVisibility.PARTIAL, "standard theoretical visibility")
    titanCheckEquals(TitanCapabilityMatrix.theoreticalVisibility(TitanPrivilegeLevel.ROOT), DataVisibility.FULL, "root theoretical visibility")
    val standard = TitanPrivilegeSnapshot(checkedAtMillis = TITAN_NOW)
    val root = rootPrivilege()
    val shizuku = TitanPrivilegeSnapshot(
        level = TitanPrivilegeLevel.SHIZUKU,
        shizukuInstalled = true,
        shizukuBridgeAvailable = true,
        build = TitanBuildIntegrity(adbWifiExposed = true),
        checkedAtMillis = TITAN_NOW,
        notes = listOf(MessageRef(TitanTextKeys.NOTE_SHIZUKU_ACTIVE)),
    )
    titanCheckEquals(shizuku.build.adbWifiExposed, true, "adb wifi build integrity preserved")
    titanCheckEquals(TitanCapabilityMatrix.effectiveCapabilities(null), emptySet<TitanCapability>(), "no privilege no capabilities")
    titanCheckEquals(TitanCapabilityMatrix.effectiveCapabilities(standard), emptySet<TitanCapability>(), "standard no capabilities")
    titanCheckEquals(TitanCapabilityMatrix.effectiveCapabilities(shizuku), expectedTheory.getValue(TitanPrivilegeLevel.SHIZUKU), "shizuku capabilities")
    val shizukuStatus = TitanStatusComposer.compose(shizuku, null, null, nowMillis = TITAN_NOW)
    titanCheckEquals(shizukuStatus.level, TitanPrivilegeLevel.SHIZUKU, "shizuku composed level")
    titanCheckTrue(shizukuStatus.has(TitanCapability.SOCKET_PROVENANCE) && shizukuStatus.has(TitanCapability.APP_FREEZE), "shizuku composed capabilities")
    titanCheckTrue(!shizukuStatus.has(TitanCapability.NETWORK_QUARANTINE) && !shizukuStatus.has(TitanCapability.PROCESS_KILL), "shizuku excludes root-only capabilities")
    titanCheckTrue(
        listOf(
            TitanTextKeys.NOTE_SHIZUKU_ACTIVE,
            TitanTextKeys.NOTE_SHIZUKU_PERMISSION_DENIED,
            TitanTextKeys.KEY_ACTIVATE_SHIZUKU_OK,
        ).all { key -> key.startsWith("titan.") },
        "shizuku text keys stable",
    )
    titanCheckEquals(TitanCapabilityMatrix.effectiveCapabilities(root), allCapabilities(), "root capabilities")
    titanCheckEquals(TitanCapabilityMatrix.effectiveVisibility(null), DataVisibility.PARTIAL, "no privilege partial")
    titanCheckEquals(TitanCapabilityMatrix.effectiveVisibility(root), DataVisibility.FULL, "root full visibility")
    listOf(standard, shizuku, root).forEach { snapshot ->
        titanCheckEquals(TitanCapabilityMatrix.effectiveVisibility(snapshot), snapshot.visibility(), "visibility matches privilege ${snapshot.level}")
    }
    val threatEngine = SocketProvenanceEngine(threatIndexProvider = { titanC2Index("45.33.32.0/24") })
    val sockets = threatEngine.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    val fim = FimEngine().compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1)), TITAN_NOW).snapshot
    val witness = TitanWitnessStatus.ready(1L, TITAN_NOW, "abcd1234")
    val status = TitanStatusComposer.compose(
        privilege = root,
        sockets = sockets,
        fim = fim,
        witness = witness,
        activeContainments = 2,
        lastScanAtMillis = TITAN_NOW,
        lastScanOutcome = TitanScanOutcome.COMPLETED,
        nowMillis = TITAN_NOW,
    )
    titanCheckEquals(status.level, TitanPrivilegeLevel.ROOT, "composed level")
    titanCheckEquals(status.visibility, DataVisibility.FULL, "composed visibility")
    titanCheckEquals(status.capabilities, allCapabilities(), "composed capabilities")
    titanCheckEquals(status.has(TitanCapability.APP_FREEZE), true, "composed has capability")
    titanCheckEquals(status.capabilityCount, TitanCapability.values().size, "composed capability count")
    titanCheckEquals(status.sockets, sockets, "composed sockets preserved")
    titanCheckEquals(status.fim, fim, "composed fim preserved")
    titanCheckEquals(status.witness, witness, "composed witness preserved")
    titanCheckEquals(status.activeContainments, 2, "composed active containments")
    titanCheckEquals(status.lastScanAtMillis, TITAN_NOW, "composed last scan")
    titanCheckEquals(status.lastScanOutcome, TitanScanOutcome.COMPLETED, "composed outcome")
    titanCheckEquals(status.attentionRequired, true, "composed attention on threat")
    titanCheckEquals(
        status.notes,
        listOf(
            MessageRef(TitanTextKeys.NOTE_SELINUX_PERMISSIVE),
            MessageRef(TitanTextKeys.NOTE_FIM_BASELINE),
            MessageRef(TitanTextKeys.NOTE_WITNESS_UNPAIRED),
        ),
        "composed notes stable order",
    )
    val emptyStatus = TitanStatusComposer.compose(null, null, null, nowMillis = TITAN_NOW)
    titanCheckEquals(emptyStatus.level, TitanPrivilegeLevel.STANDARD, "empty composed level")
    titanCheckEquals(emptyStatus.capabilities, emptySet<TitanCapability>(), "empty composed capabilities")
    titanCheckEquals(emptyStatus.witness, TitanWitnessStatus.UNAVAILABLE, "empty composed witness")
    titanCheckEquals(emptyStatus.notes, emptyList<MessageRef>(), "empty composed notes")
    titanCheckEquals(emptyStatus.attentionRequired, false, "empty composed attention")
    titanCheckEquals(emptyStatus.lastScanOutcome, TitanScanOutcome.NEVER, "empty composed outcome")
    val deltaPipeline = FimEngine()
    val baseline = deltaPipeline.compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1)), TITAN_NOW).newBaseline
    val deltaSnapshot = deltaPipeline.compare(
        baseline, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1), scannedFile("$TITAN_TMP_ROOT/new.sh", 2)), TITAN_NOW + 1_000L,
    ).snapshot
    titanCheckEquals(
        TitanStatusComposer.compose(standard, null, deltaSnapshot, nowMillis = TITAN_NOW).attentionRequired,
        true,
        "composed attention on FIM delta",
    )
    val dirtyRoot = TitanPrivilegeSnapshot(suPaths = listOf("/system/xbin/su"), checkedAtMillis = TITAN_NOW)
    titanCheckEquals(
        TitanStatusComposer.compose(dirtyRoot, null, null, nowMillis = TITAN_NOW).attentionRequired,
        true,
        "composed attention on dirty root",
    )
    titanCheckEquals(TitanStatusComposer.running(status, TITAN_NOW).lastScanOutcome, TitanScanOutcome.RUNNING, "running outcome")
    titanCheckEquals(TitanStatusComposer.running(status, TITAN_NOW).sockets, status.sockets, "running keeps evidence")
    titanCheckEquals(TitanStatusComposer.running(null, TITAN_NOW), TitanStatus.empty(TITAN_NOW).copy(lastScanOutcome = TitanScanOutcome.RUNNING), "running from empty")
    titanCheckEquals(TitanStatusComposer.empty(TITAN_NOW), TitanStatus.empty(TITAN_NOW), "composer empty state")
    titanCheckEquals(TitanStatusComposer.socketVisibility(status), DataVisibility.FULL, "socket visibility passthrough")
    titanCheckEquals(TitanStatusComposer.socketVisibility(emptyStatus), DataVisibility.PARTIAL, "socket visibility fallback")
    TitanCapability.values().forEach { capability ->
        titanCheckEquals(TitanStatusComposer.capabilityLabelId(capability), capability.id, "capability label ${capability.id}")
    }
    val extraNotes = (0 until 12).map { index -> MessageRef("titan.note.extra$index") }
    val withExtras = TitanStatusComposer.compose(null, null, null, extraNotes = extraNotes, nowMillis = TITAN_NOW)
    titanCheckEquals(withExtras.notes.size, 8, "extra notes capped")
}

// --- event factory tests -----------------------------------------------------------------------

private fun testEvents() {
    val factory = TitanEventFactory
    titanCheckEquals(factory.privilegeEvent(TITAN_DEVICE_ID, 34, TitanPrivilegeSnapshot(checkedAtMillis = TITAN_NOW), TITAN_NOW), null, "clean standard has no event")
    val dirty = factory.privilegeEvent(
        TITAN_DEVICE_ID, 34,
        TitanPrivilegeSnapshot(suPaths = listOf("/system/xbin/su"), checkedAtMillis = TITAN_NOW), TITAN_NOW,
    )
    titanCheckTrue(dirty != null, "dirty root emits event")
    val dirtyEvent = dirty ?: error("dirty event missing")
    titanCheckEquals(dirtyEvent.eventClass, EventClass.TV_DEVICE_STATE, "privilege event class")
    titanCheckEquals(dirtyEvent.collectorId, factory.COLLECTOR_GATE, "privilege collector")
    titanCheckEquals(dirtyEvent.ruleId, factory.RULE_ROOT_AUDIT, "privilege rule")
    titanCheckEquals(dirtyEvent.severity, Severity.HIGH, "dirty root severity")
    titanCheckEquals(dirtyEvent.policyAction, PolicyAction.ESCALATE_TO_USER, "privilege policy")
    titanCheckEquals(dirtyEvent.confidence, Confidence.HIGH, "privilege confidence")
    titanCheckEquals(dirtyEvent.subject, "titan-privilege", "privilege subject")
    titanCheckEquals(dirtyEvent.attributes["level"], "standard", "privilege level attribute")
    titanCheckEquals(dirtyEvent.attributes["test_keys"], "false", "privilege test keys attribute")
    titanCheckTrue(dirtyEvent.attributes.containsKey("root_kind") && dirtyEvent.attributes.containsKey("selinux"), "privilege attributes present")
    checkEventInvariants(dirtyEvent, "privilege")
    val testKeys = factory.privilegeEvent(TITAN_DEVICE_ID, 34, TitanPrivilegeSnapshot(build = TitanBuildIntegrity(testKeys = true), checkedAtMillis = TITAN_NOW), TITAN_NOW)
    titanCheckEquals(testKeys?.severity, Severity.LOW, "test keys low severity")
    val permissive = factory.privilegeEvent(
        TITAN_DEVICE_ID, 34, TitanPrivilegeSnapshot(build = TitanBuildIntegrity(selinuxEnforcing = false), checkedAtMillis = TITAN_NOW), TITAN_NOW,
    )
    titanCheckEquals(permissive?.severity, Severity.HIGH, "permissive selinux high severity")
    val adb = factory.privilegeEvent(
        TITAN_DEVICE_ID, 34, TitanPrivilegeSnapshot(build = TitanBuildIntegrity(adbTcpExposed = true), checkedAtMillis = TITAN_NOW), TITAN_NOW,
    )
    titanCheckEquals(adb?.attributes?.get("adb_tcp"), "exposed", "adb attribute on privilege event")
    titanCheckEquals(factory.privilegeEvent(TITAN_DEVICE_ID, 34, rootPrivilege(), TITAN_NOW)?.severity, Severity.MEDIUM, "root privilege severity")
    val threatEngine = SocketProvenanceEngine(threatIndexProvider = { titanC2Index("45.33.32.0/24") })
    val threatObservation = threatEngine.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW).observations.single()
    val threatEvent = factory.threatSocketEvent(TITAN_DEVICE_ID, 34, threatObservation, TITAN_NOW)
    titanCheckEquals(threatEvent.eventClass, EventClass.TV_TI_MATCH, "threat event class")
    titanCheckEquals(threatEvent.collectorId, factory.COLLECTOR_SOCKET, "threat collector")
    titanCheckEquals(threatEvent.ruleId, factory.RULE_C2_SOCKET, "threat rule")
    titanCheckEquals(threatEvent.severity, Severity.CRITICAL, "threat severity")
    titanCheckEquals(threatEvent.subject, threatObservation.subject, "threat subject")
    titanCheckEquals(threatEvent.attributes["remote"], "45.33.32.7:443", "threat remote attribute")
    titanCheckEquals(threatEvent.attributes["feeds"], "feodo", "threat feeds attribute")
    checkEventInvariants(threatEvent, "threat-socket")
    val unattributedObservation = SocketProvenanceEngine()
        .analyze(listOf(rawSocket(99L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW).observations.single()
    val unattributedEvent = factory.unattributedSocketEvent(TITAN_DEVICE_ID, 34, unattributedObservation, TITAN_NOW)
    titanCheckEquals(unattributedEvent.ruleId, factory.RULE_UNATTRIBUTED_SOCKET, "unattributed rule")
    titanCheckEquals(unattributedEvent.severity, Severity.MEDIUM, "unattributed severity")
    titanCheckEquals(unattributedEvent.policyAction, PolicyAction.RECOMMEND_MANUAL, "unattributed policy")
    titanCheckEquals(unattributedEvent.attributes["inode"], "99", "unattributed inode attribute")
    checkEventInvariants(unattributedEvent, "unattributed-socket")
    val adbObservation = SocketProvenanceEngine().analyze(
        listOf(rawSocket(50L, state = SocketState.LISTEN, localPort = 5_555, remoteAddress = "0.0.0.0", remotePort = 0, uid = 0)),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    ).observations.single()
    val adbEvent = factory.adbExposureEvent(TITAN_DEVICE_ID, 34, adbObservation, TITAN_NOW)
    titanCheckEquals(adbEvent.subject, "adb-port", "ADB event subject")
    titanCheckEquals(adbEvent.ruleId, factory.RULE_ADB_EXPOSED, "ADB event rule")
    titanCheckEquals(adbEvent.severity, Severity.HIGH, "ADB event severity")
    titanCheckEquals(adbEvent.attributes["local_port"], "5555", "ADB local port attribute")
    checkEventInvariants(adbEvent, "adb-exposure")
    titanCheckEquals(factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, fimObservation("$TITAN_TMP_ROOT/a.sh", 1, FimStatus.BASELINE_CREATED), TITAN_NOW), null, "baseline created has no FIM event")
    titanCheckEquals(factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, fimObservation("$TITAN_TMP_ROOT/a.sh", 1, FimStatus.MATCHES_BASELINE), TITAN_NOW), null, "match has no FIM event")
    titanCheckEquals(factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, fimObservation("$TITAN_TMP_ROOT/a.sh", 1, FimStatus.UNREADABLE, readable = false), TITAN_NOW), null, "unreadable has no FIM event")
    val newFileEvent = factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, fimObservation("$TITAN_TMP_ROOT/a.sh", 1, FimStatus.NEW_FILE), TITAN_NOW)
    titanCheckEquals(newFileEvent?.eventClass, EventClass.TV_ENFORCEMENT, "new file event class")
    titanCheckEquals(newFileEvent?.severity, Severity.HIGH, "new file severity")
    titanCheckEquals(newFileEvent?.ruleId, factory.RULE_FIM_DELTA, "new file rule")
    titanCheckEquals(newFileEvent?.attributes?.get("status"), "new_file", "new file status attribute")
    titanCheckEquals(newFileEvent?.attributes?.get("hash")?.length, 16, "hash prefix attribute")
    checkEventInvariants(newFileEvent ?: error("new file event missing"), "fim-new")
    titanCheckEquals(
        factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, fimObservation("$TITAN_TMP_ROOT/a.sh", 1, FimStatus.MODIFIED), TITAN_NOW)?.severity,
        Severity.MEDIUM,
        "modified file severity",
    )
    val containment = factory.containmentEvent(TITAN_DEVICE_ID, 34, actionResult(ok = true, verified = true), "user_initiated", TITAN_NOW)
    titanCheckEquals(containment.collectorId, factory.COLLECTOR_RESPONSE, "containment collector")
    titanCheckEquals(containment.ruleId, factory.RULE_CONTAINMENT, "containment rule")
    titanCheckEquals(containment.severity, Severity.MEDIUM, "successful containment severity")
    titanCheckEquals(containment.confidence, Confidence.HIGH, "verified containment confidence")
    titanCheckEquals(containment.subject, "freeze_app:com.example.app", "containment subject")
    titanCheckEquals(containment.attributes["ok"], "true", "containment ok attribute")
    titanCheckEquals(containment.attributes["failure"], "none", "containment failure attribute")
    checkEventInvariants(containment, "containment-success")
    val failedContainment = factory.containmentEvent(
        TITAN_DEVICE_ID, 34, actionResult(ok = false, verified = false, failure = TitanActionFailure.COMMAND_FAILED), "C2_SOCKET", TITAN_NOW,
    )
    titanCheckEquals(failedContainment.severity, Severity.HIGH, "failed containment severity")
    titanCheckEquals(failedContainment.confidence, Confidence.MEDIUM, "failed containment confidence")
    titanCheckEquals(failedContainment.attributes["failure"], "command_failed", "failed containment attribute")
    checkEventInvariants(failedContainment, "containment-failure")
    val checkpoint = TitanWitnessCheckpointFactory.create(TITAN_DEVICE_ID, 1L, TITAN_NOW, listOf(ledgerRow1), witnessKey)
    val witnessEvent = factory.witnessCheckpointEvent(TITAN_DEVICE_ID, 34, checkpoint, TITAN_NOW)
    titanCheckEquals(witnessEvent.severity, Severity.INFO, "witness severity")
    titanCheckEquals(witnessEvent.policyAction, PolicyAction.NONE, "witness policy")
    titanCheckEquals(witnessEvent.collectorId, factory.COLLECTOR_WITNESS, "witness collector")
    titanCheckEquals(witnessEvent.attributes["seq"], "1", "witness sequence attribute")
    checkEventInvariants(witnessEvent, "witness")
    val longPathObservation = fimObservation("$TITAN_TMP_ROOT/" + "a".repeat(180), 1, FimStatus.NEW_FILE)
    val sanitized = factory.fimDeltaEvent(TITAN_DEVICE_ID, 34, longPathObservation, 0L)
    titanCheckTrue(sanitized != null && sanitized.subject.length <= 160, "long subject sanitized")
    titanCheckEquals(sanitized?.eventTimeMillis, 1L, "event time clamped")
    checkEventInvariants(sanitized ?: error("sanitized event missing"), "sanitized")
    titanCheckThrows<IllegalArgumentException>("invalid device id rejected by event model") {
        factory.threatSocketEvent("tv_NOTHEX", 34, threatObservation, TITAN_NOW)
    }
    titanCheckEquals(factory.isThreatRisk(threatObservation), true, "threat observation flagged")
    titanCheckEquals(factory.isThreatRisk(unattributedObservation), false, "unattributed observation not threat")
    listOf(
        dirtyEvent, testKeys ?: error("test keys event missing"), permissive ?: error("permissive event missing"),
        adb ?: error("adb event missing"), threatEvent, unattributedEvent, adbEvent,
        newFileEvent ?: error("new file event missing"), containment, failedContainment, witnessEvent,
    ).forEachIndexed { index, event -> checkEventInvariants(event, "event-$index") }
}

// --- source/build checks -----------------------------------------------------------------------

/** String literals are data, not API usage: the protected-package catalog legitimately lists
 *  package names such as `com.google.android.apps.*`. */
private val TITAN_STRING_LITERAL = Regex("\"[^\"]*\"")

private fun testSourceAndBuild() {
    val titanRoot = File("src/main/kotlin/de/visiongaia/gedefense/tv/core/titan")
    titanCheckTrue(titanRoot.isDirectory, "titan source directory exists")
    val files = titanRoot.walkTopDown().filter { file -> file.isFile && file.extension == "kt" }.toList()
    titanCheckTrue(files.size >= 12, "titan source files present (${files.size})")
    listOf("proc", "fim", "witness", "model", "events", "response").forEach { directory ->
        titanCheckTrue(File(titanRoot, directory).isDirectory, "titan/$directory directory exists")
    }
    files.forEach { file ->
        val lines = file.readLines()
        titanCheckTrue(lines.size <= 500, "titan file ${file.name} within 500 lines (${lines.size})")
        lines.forEachIndexed { index, rawLine ->
            val line = rawLine.trimStart()
            titanCheckTrue(!line.startsWith("import android"), "no Android import in ${file.name}:${index + 1}")
            val code = rawLine.replace(TITAN_STRING_LITERAL, "")
            titanCheckTrue(!code.contains("android."), "no Android API in ${file.name}:${index + 1}")
        }
        val text = file.readText()
        listOf("TODO", "FIXME", "NotImplementedError", "java.util.Random", "!!").forEach { marker ->
            titanCheckTrue(!text.contains(marker), "no '$marker' in ${file.name}")
        }
    }
    val witnessSource = File(titanRoot, "witness/TitanWitnessCheckpointFactory.kt").readText()
    titanCheckTrue(witnessSource.contains("MessageDigest.isEqual"), "witness uses constant-time comparison")
    titanCheckTrue(witnessSource.contains("HmacSHA256"), "witness uses HMAC-SHA256")
    titanCheckTrue(!File(titanRoot, "proc/ProcNetParser.kt").readText().contains("currentTimeMillis"), "parser invents no clock")
    titanCheckTrue(!File(titanRoot, "proc/SocketProvenanceEngine.kt").readText().contains("currentTimeMillis"), "socket engine invents no clock")
    val buildFile = File("build.gradle.kts")
    titanCheckTrue(buildFile.isFile, "build file present")
    val buildText = buildFile.readText()
    titanCheckTrue(buildText.contains("tvTitanCheck"), "titan verification task registered")
    titanCheckTrue(buildText.contains("TitanTestMainKt"), "titan harness main class wired")
    titanCheckTrue(buildText.contains("tvKineticCheck") && buildText.contains("tvV2Check") && buildText.contains("tvCoreCheck"), "earlier verification tasks preserved")
    titanCheckTrue(buildText.contains("""implementation(project(":core"))"""), "vendored core dependency preserved")
    titanCheckTrue(buildText.contains("jvmToolchain(17)"), "JVM toolchain 17 preserved")
    titanCheckEquals(SocketProvenanceConfig.DEFAULT.maxSockets, 4_096, "socket default max sockets")
    titanCheckEquals(SocketProvenanceConfig.DEFAULT.maxObservations, 512, "socket default max observations")
    titanCheckEquals(SocketProvenanceConfig.DEFAULT.maxProcessEntries, 4_096, "socket default process cap")
    titanCheckEquals(SocketProvenanceConfig.DEFAULT.adbPort, 5_555, "socket default ADB port")
    titanCheckEquals(FimSnapshot.MAX_OBSERVATIONS, 512, "FIM observation cap")
    titanCheckEquals(FimBaseline.MAX_ENTRIES, 4_096, "FIM baseline cap")
    titanCheckEquals(TitanFimPolicy.DEFAULT_ROOTS.size, 6, "FIM watch root count")
    titanCheckEquals(TitanFimPolicy.DEFAULT_ROOTS.map { root -> root.path }.distinct().size, 6, "FIM watch roots distinct")
    titanCheckTrue(TitanFimPolicy.isWatched("$TITAN_TMP_ROOT/a.sh"), "watch policy covers tmp")
    titanCheckTrue(!TitanFimPolicy.isWatched("/etc/passwd"), "watch policy excludes etc")
    titanCheckTrue(TitanFimPolicy.isSafeAbsolutePath("/data/local/gedefense_vault/x"), "vault path safe")
    titanCheckTrue(!TitanFimPolicy.isSafeAbsolutePath("/data/local/tmp/../etc"), "traversal path unsafe")
}

internal fun registerMatrixEventTests() {
    titanTest("matrix+composer: capability/visibility/status consistency", ::testMatrixComposer)
    titanTest("events: field validation, all factories, no-throw", ::testEvents)
    titanTest("source: no Android imports in titan package + build wiring", ::testSourceAndBuild)
}
