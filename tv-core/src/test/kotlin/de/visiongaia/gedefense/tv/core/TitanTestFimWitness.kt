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

// --- FIM tests ---------------------------------------------------------------------------------

private fun firstBaseline(): FimBaseline? =
    FimEngine().compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10), scannedFile("$TITAN_TMP_ROOT/b.sh", 2, 20)), TITAN_NOW).newBaseline

private fun testFimBaselineCreation() {
    val engine = FimEngine()
    val scan = listOf(
        scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10),
        scannedFile("$TITAN_TMP_ROOT/b.sh", 2, 20),
        scannedFile("$TITAN_TMP_ROOT/c.sh", 3, 30, readable = false),
    )
    val result = engine.compare(null, scan, TITAN_NOW)
    titanCheckEquals(result.baselineChanged, true, "first run changes baseline")
    titanCheckEquals(result.snapshot.baselineCreated, true, "first run baseline created")
    titanCheckEquals(result.snapshot.baselineAtMillis, TITAN_NOW, "first run baseline timestamp")
    titanCheckEquals(result.snapshot.capturedAtMillis, TITAN_NOW, "first run capture time")
    titanCheckEquals(result.snapshot.scannedFiles, 3, "first run scanned count")
    titanCheckEquals(result.snapshot.newFiles, 0, "first run no new files")
    titanCheckEquals(result.snapshot.modifiedFiles, 0, "first run no modified files")
    titanCheckEquals(result.snapshot.unreadableFiles, 1, "first run unreadable count")
    titanCheckEquals(result.snapshot.visibility, DataVisibility.PARTIAL, "first run unreadable partial visibility")
    titanCheckEquals(result.snapshot.note, MessageRef(TitanTextKeys.NOTE_FIM_BASELINE), "first run baseline note")
    titanCheckEquals(result.newBaseline?.entries?.map { entry -> entry.path }, listOf("$TITAN_TMP_ROOT/a.sh", "$TITAN_TMP_ROOT/b.sh"), "baseline entries sorted")
    titanCheckEquals(result.newBaseline?.createdAtMillis, TITAN_NOW, "baseline creation time")
    titanCheckEquals(result.newBaseline?.entries?.first()?.sha256, fakeHash(1), "baseline hash stored")
    titanCheckEquals(
        result.snapshot.observations.map { observation -> "${observation.path}:${observation.status}" },
        listOf(
            "$TITAN_TMP_ROOT/c.sh:UNREADABLE",
            "$TITAN_TMP_ROOT/a.sh:BASELINE_CREATED",
            "$TITAN_TMP_ROOT/b.sh:BASELINE_CREATED",
        ),
        "first run status codes and ordering",
    )
    val clean = engine.compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1)), TITAN_NOW)
    titanCheckEquals(clean.snapshot.visibility, DataVisibility.FULL, "first run clean visibility")
    titanCheckEquals(clean.snapshot.note, MessageRef(TitanTextKeys.NOTE_FIM_BASELINE), "first run clean note")
    val emptyScan = engine.compare(null, emptyList(), TITAN_NOW)
    titanCheckEquals(emptyScan.snapshot.scannedFiles, 0, "empty first run scanned")
    titanCheckEquals(emptyScan.snapshot.visibility, DataVisibility.PARTIAL, "empty first run visibility")
    titanCheckEquals(emptyScan.newBaseline?.entries, emptyList<FimBaselineEntry>(), "empty first baseline")
    titanCheckEquals(emptyScan.baselineChanged, true, "empty first run changes baseline")
}

private fun testFimDelta() {
    val engine = FimEngine()
    val baseline = firstBaseline()
    val second = engine.compare(
        baseline,
        listOf(
            scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10),
            scannedFile("$TITAN_TMP_ROOT/b.sh", 9, 20),
            scannedFile("$TITAN_TMP_ROOT/d.sh", 4, 40),
        ),
        TITAN_NOW + 1_000L,
    )
    titanCheckEquals(second.snapshot.baselineCreated, false, "delta run no baseline creation")
    titanCheckEquals(second.baselineChanged, true, "delta run changes baseline")
    titanCheckEquals(second.snapshot.newFiles, 1, "delta new file count")
    titanCheckEquals(second.snapshot.modifiedFiles, 1, "delta modified file count")
    titanCheckEquals(second.snapshot.unreadableFiles, 0, "delta unreadable count")
    titanCheckEquals(second.snapshot.scannedFiles, 3, "delta scanned count")
    titanCheckEquals(second.snapshot.deltaCount, 2, "delta count")
    titanCheckEquals(second.snapshot.visibility, DataVisibility.FULL, "delta visibility")
    titanCheckEquals(second.snapshot.note, null, "delta note")
    titanCheckEquals(second.snapshot.baselineAtMillis, TITAN_NOW, "delta baseline timestamp retained")
    titanCheckEquals(
        second.snapshot.observations.map { observation -> "${observation.path}:${observation.status}" },
        listOf(
            "$TITAN_TMP_ROOT/d.sh:NEW_FILE",
            "$TITAN_TMP_ROOT/b.sh:MODIFIED",
            "$TITAN_TMP_ROOT/a.sh:MATCHES_BASELINE",
        ),
        "delta status codes and ordering",
    )
    val secondBaseline = second.newBaseline
    titanCheckEquals(secondBaseline?.entries?.size, 3, "delta baseline entries")
    titanCheckEquals(secondBaseline?.entries?.first { entry -> entry.path == "$TITAN_TMP_ROOT/b.sh" }?.sha256, fakeHash(9), "modified hash updated")
    val repeat = engine.compare(
        secondBaseline,
        listOf(
            scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10),
            scannedFile("$TITAN_TMP_ROOT/b.sh", 9, 20),
            scannedFile("$TITAN_TMP_ROOT/d.sh", 4, 40),
        ),
        TITAN_NOW + 2_000L,
    )
    titanCheckEquals(repeat.baselineChanged, false, "match-only run keeps baseline")
    titanCheckEquals(repeat.snapshot.newFiles, 0, "match-only no new files")
    titanCheckEquals(repeat.snapshot.modifiedFiles, 0, "match-only no modified")
    titanCheckEquals(repeat.newBaseline, secondBaseline, "match-only baseline stable")
    val retention = engine.compare(baseline, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10)), TITAN_NOW + 3_000L)
    titanCheckEquals(retention.snapshot.scannedFiles, 1, "retention scanned")
    titanCheckEquals(retention.newBaseline?.entries?.map { entry -> entry.path }, listOf("$TITAN_TMP_ROOT/a.sh", "$TITAN_TMP_ROOT/b.sh"), "missing baseline entry retained")
    titanCheckEquals(retention.baselineChanged, false, "retention does not change baseline")
    val unreadable = engine.compare(baseline, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10, readable = false)), TITAN_NOW + 4_000L)
    titanCheckEquals(unreadable.snapshot.unreadableFiles, 1, "unreadable later count")
    titanCheckEquals(unreadable.snapshot.visibility, DataVisibility.PARTIAL, "unreadable later visibility")
    titanCheckEquals(unreadable.snapshot.note, MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE), "unreadable note")
    titanCheckEquals(unreadable.newBaseline?.entries?.firstOrNull { entry -> entry.path == "$TITAN_TMP_ROOT/a.sh" }?.sha256, fakeHash(1), "unreadable keeps baseline hash")
    val unreadableNew = engine.compare(baseline, listOf(scannedFile("$TITAN_TMP_ROOT/z.sh", 5, readable = false)), TITAN_NOW + 5_000L)
    titanCheckEquals(unreadableNew.newBaseline?.entries?.any { entry -> entry.path == "$TITAN_TMP_ROOT/z.sh" }, false, "unreadable new path not baselined")
    val sameHashOtherSize = engine.compare(baseline, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 500)), TITAN_NOW + 6_000L)
    titanCheckEquals(sameHashOtherSize.snapshot.observations.first { observation -> observation.path == "$TITAN_TMP_ROOT/a.sh" }.status, FimStatus.MODIFIED, "size change is modification")
}

private fun testFimBounds() {
    val engine = FimEngine()
    val duplicate = engine.compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1), scannedFile("$TITAN_TMP_ROOT/a.sh", 2)), TITAN_NOW)
    titanCheckEquals(duplicate.snapshot.scannedFiles, 1, "duplicate path deduplicated")
    titanCheckEquals(duplicate.snapshot.truncated, true, "duplicate path flagged truncation")
    titanCheckEquals(duplicate.newBaseline?.entries?.single()?.sha256, fakeHash(1), "first duplicate wins")
    val perRoot = FimEngine(config = FimConfig(maxFilesPerRoot = 1, maxTotalFiles = 16))
    val perRootResult = perRoot.compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/b.sh", 2), scannedFile("$TITAN_TMP_ROOT/a.sh", 1)), TITAN_NOW)
    titanCheckEquals(perRootResult.snapshot.scannedFiles, 1, "per-root cap")
    titanCheckEquals(perRootResult.snapshot.observations.single().path, "$TITAN_TMP_ROOT/a.sh", "per-root deterministic pick")
    titanCheckEquals(perRootResult.snapshot.truncated, true, "per-root truncation")
    val totalCap = FimEngine(config = FimConfig(maxFilesPerRoot = 2_048, maxTotalFiles = 1))
    val totalResult = totalCap.compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10), scannedFile("$TITAN_TMP_ROOT/b.sh", 2, 20)), TITAN_NOW)
    titanCheckEquals(totalResult.snapshot.scannedFiles, 1, "total cap")
    titanCheckEquals(totalResult.snapshot.truncated, true, "total cap truncation")
    val narrowRoots = FimEngine(config = FimConfig(roots = listOf(FimWatchRoot(TITAN_TMP_ROOT, recursive = true, maxDepth = 2))))
    val outside = narrowRoots.compare(
        null,
        listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1), scannedFile("/system/bin/sh", 2, root = "/system/bin")),
        TITAN_NOW,
    )
    titanCheckEquals(outside.snapshot.scannedFiles, 1, "unconfigured root dropped")
    titanCheckEquals(outside.snapshot.truncated, true, "unconfigured root truncation")
    titanCheckEquals(outside.newBaseline?.entries?.single()?.path, "$TITAN_TMP_ROOT/a.sh", "unconfigured root not baselined")
    val largeConfig = FimEngine(config = FimConfig(maxFilesPerRoot = 2_048, maxTotalFiles = 2_048))
    val manyFiles = (0 until 600).map { index -> scannedFile("$TITAN_TMP_ROOT/f%03d".format(index), index, 10L) }
    val manyResult = largeConfig.compare(null, manyFiles, TITAN_NOW)
    titanCheckEquals(manyResult.snapshot.observations.size, FimSnapshot.MAX_OBSERVATIONS, "observation cap")
    titanCheckEquals(manyResult.snapshot.scannedFiles, 600, "observation cap scanned count")
    titanCheckEquals(manyResult.snapshot.truncated, true, "observation cap truncated")
    titanCheckEquals(manyResult.newBaseline?.entries?.size, 600, "baseline holds all bounded files")
    val fullBaseline = FimBaseline(
        entries = (0 until FimBaseline.MAX_ENTRIES).map { index ->
            FimBaselineEntry("$TITAN_TMP_ROOT/b%04d".format(index), fakeHash(index), 10L, TITAN_NOW, "0644")
        },
        createdAtMillis = TITAN_NOW,
    )
    val baselineCap = engine.compare(fullBaseline, listOf(scannedFile("$TITAN_TMP_ROOT/a-new", 9_999)), TITAN_NOW + 1_000L)
    titanCheckEquals(baselineCap.newBaseline?.entries?.size, FimBaseline.MAX_ENTRIES, "baseline entry cap")
    titanCheckEquals(baselineCap.snapshot.truncated, true, "baseline cap truncation")
    titanCheckEquals(baselineCap.baselineChanged, true, "baseline cap changes baseline")
    val unordered = listOf(
        scannedFile("$TITAN_TMP_ROOT/c.sh", 3, 30, readable = false),
        scannedFile("$TITAN_TMP_ROOT/a.sh", 1, 10),
        scannedFile("$TITAN_TMP_ROOT/b.sh", 2, 20),
    )
    val forward = engine.compare(null, unordered, TITAN_NOW)
    val reversed = engine.compare(null, unordered.reversed(), TITAN_NOW)
    titanCheckEquals(forward, reversed, "deterministic across input order")
    val clocked = FimEngine(clock = { 123_456_789L }).compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1)))
    titanCheckEquals(clocked.snapshot.capturedAtMillis, 123_456_789L, "clock overload used")
    val clampedClock = FimEngine(clock = { 0L }).compare(null, listOf(scannedFile("$TITAN_TMP_ROOT/a.sh", 1)))
    titanCheckEquals(clampedClock.snapshot.capturedAtMillis, 1L, "clock clamps non-positive")
    val longPath = "$TITAN_TMP_ROOT/" + "a".repeat(200)
    val longResult = engine.compare(null, listOf(scannedFile(longPath, 7)), TITAN_NOW)
    titanCheckEquals(longResult.snapshot.observations.single().path, longPath, "long safe path tolerated")
    titanCheckTrue(longResult.snapshot.observations.single().sha256 == fakeHash(7), "long path hash retained")
    titanCheckThrows<IllegalArgumentException>("relative scanned path rejected by model") {
        FimScannedFile("relative/path", fakeHash(1), 1L, TITAN_NOW, "0644", TITAN_TMP_ROOT, true)
    }
    titanCheckThrows<IllegalArgumentException>("readable without hash rejected by model") {
        FimScannedFile("$TITAN_TMP_ROOT/x", null, 1L, TITAN_NOW, "0644", TITAN_TMP_ROOT, true)
    }
    titanCheckThrows<IllegalArgumentException>("duplicate baseline path rejected by model") {
        FimBaseline(
            listOf(
                FimBaselineEntry("$TITAN_TMP_ROOT/x", fakeHash(1), 1L, TITAN_NOW, "0644"),
                FimBaselineEntry("$TITAN_TMP_ROOT/x", fakeHash(2), 1L, TITAN_NOW, "0644"),
            ),
            TITAN_NOW,
        )
    }
}

// --- witness tests -----------------------------------------------------------------------------

private fun testWitness() {
    val factory = TitanWitnessCheckpointFactory
    titanCheckEquals(factory.MAX_ROWS, 200, "witness row cap")
    titanCheckEquals(
        factory.ledgerDigest(emptyList()),
        "b5588adff9ad9ab5aee61b67ad7a3ea44e0ca0ae144f66075035453571353951",
        "ledger digest domain KAT",
    )
    titanCheckEquals(
        factory.ledgerDigest(listOf(ledgerRow1)),
        "5ecacfc9a5d7c1c133854c66ec09bfa59d6bdc2a9d0c447d466db3956809c349",
        "single row digest KAT",
    )
    titanCheckEquals(
        factory.ledgerDigest(listOf(ledgerRow1, ledgerRow2)),
        "81f9f6747bd808d98ff81c7991a6d5de283a8bf05c6d9ce66a9995cb4a673a1d",
        "two row digest KAT",
    )
    titanCheckEquals(factory.ledgerDigest(listOf(ledgerRow1)).length, 64, "digest hex length")
    val checkpoint = factory.create(TITAN_DEVICE_ID, 7L, 1_700_000_000_000L, listOf(ledgerRow1), witnessKey)
    titanCheckEquals(checkpoint.sequence, 7L, "checkpoint sequence")
    titanCheckEquals(checkpoint.issuedAtMillis, 1_700_000_000_000L, "checkpoint timestamp")
    titanCheckEquals(
        checkpoint.ledgerDigestHex,
        "5ecacfc9a5d7c1c133854c66ec09bfa59d6bdc2a9d0c447d466db3956809c349",
        "checkpoint digest KAT",
    )
    titanCheckEquals(
        checkpoint.macHex,
        "2f36f772331c90cb18957a82f8dafca40b9338cd3b4b0b1d1308d64bc7162b4f",
        "checkpoint HMAC KAT",
    )
    titanCheckTrue(factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey), "valid checkpoint verifies")
    titanCheckEquals(factory.create(TITAN_DEVICE_ID, 7L, 1_700_000_000_000L, listOf(ledgerRow1), witnessKey), checkpoint, "create deterministic")
    titanCheckTrue(!factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow1), otherKey), "wrong key rejected")
    titanCheckTrue(!factory.verify(checkpoint, "tv_" + "0".repeat(32), listOf(ledgerRow1), witnessKey), "wrong device rejected")
    titanCheckTrue(!factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow2), witnessKey), "changed rows rejected")
    titanCheckTrue(!factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow1, ledgerRow2), witnessKey), "extra row rejected")
    titanCheckTrue(!factory.verify(checkpoint, TITAN_DEVICE_ID, emptyList(), witnessKey), "empty rows rejected")
    titanCheckTrue(!factory.verify(checkpoint.copy(sequence = 8L), TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey), "sequence tamper rejected")
    titanCheckTrue(
        !factory.verify(checkpoint.copy(issuedAtMillis = 1_700_000_000_001L), TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey),
        "timestamp tamper rejected",
    )
    titanCheckTrue(
        !factory.verify(checkpoint.copy(ledgerDigestHex = flipHex(checkpoint.ledgerDigestHex)), TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey),
        "digest tamper rejected",
    )
    titanCheckTrue(
        !factory.verify(checkpoint.copy(macHex = flipHex(checkpoint.macHex)), TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey),
        "mac tamper rejected",
    )
    titanCheckTrue(
        !factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow1.copy(subject = "tampered|1.2.3.4:80|TCP")), witnessKey),
        "subject tamper rejected",
    )
    val twoRowCheckpoint = factory.create(TITAN_DEVICE_ID, 8L, 1_700_000_000_000L, listOf(ledgerRow1, ledgerRow2), witnessKey)
    titanCheckTrue(factory.verify(twoRowCheckpoint, TITAN_DEVICE_ID, listOf(ledgerRow1, ledgerRow2), witnessKey), "two row checkpoint verifies")
    titanCheckTrue(
        !factory.verify(twoRowCheckpoint, TITAN_DEVICE_ID, listOf(ledgerRow2, ledgerRow1), witnessKey),
        "row order bound into digest",
    )
}

private fun flipHex(hex: String): String {
    val replacement = if (hex.first() == '0') '1' else '0'
    return replacement + hex.substring(1)
}

private fun testWitnessValidation() {
    val factory = TitanWitnessCheckpointFactory
    titanCheckThrows<IllegalArgumentException>("uppercase type rejected") { LedgerRow(TITAN_NOW, "Titan-Fim", "x") }
    titanCheckThrows<IllegalArgumentException>("empty type rejected") { LedgerRow(TITAN_NOW, "", "x") }
    titanCheckThrows<IllegalArgumentException>("space in type rejected") { LedgerRow(TITAN_NOW, "titan fim", "x") }
    titanCheckThrows<IllegalArgumentException>("negative row time rejected") { LedgerRow(-1L, "titan-fim", "x") }
    titanCheckThrows<IllegalArgumentException>("empty subject rejected") { LedgerRow(TITAN_NOW, "titan-fim", "") }
    titanCheckThrows<IllegalArgumentException>("newline subject rejected") { LedgerRow(TITAN_NOW, "titan-fim", "a\nb") }
    titanCheckThrows<IllegalArgumentException>("long subject rejected") { LedgerRow(TITAN_NOW, "titan-fim", "a".repeat(257)) }
    titanCheckEquals(LedgerRow(TITAN_NOW, "titan-fim", "a|b").subject, "a|b", "pipe is allowed in subject")
    titanCheckEquals(LedgerRow(TITAN_NOW, "scan.completed", "x").type, "scan.completed", "dotted evidence type accepted")
    titanCheckEquals(LedgerRow(TITAN_NOW, "tv.event", "x").type, "tv.event", "dotted tv event type accepted")
    titanCheckThrows<IllegalArgumentException>("uppercase dotted type rejected") { LedgerRow(TITAN_NOW, "Scan.Completed", "x") }
    titanCheckThrows<IllegalArgumentException>("space in dotted type rejected") { LedgerRow(TITAN_NOW, "scan completed", "x") }
    titanCheckEquals(
        factory.ledgerDigest(listOf(LedgerRow(TITAN_NOW, "scan.completed", "x"))).length,
        64,
        "dotted type participates in the digest",
    )
    titanCheckThrows<IllegalArgumentException>("invalid device id rejected") { factory.create("tv_xyz", 1L, TITAN_NOW, emptyList(), witnessKey) }
    titanCheckThrows<IllegalArgumentException>("empty device id rejected") { factory.create("", 1L, TITAN_NOW, emptyList(), witnessKey) }
    titanCheckThrows<IllegalArgumentException>("sequence zero rejected") { factory.create(TITAN_DEVICE_ID, 0L, TITAN_NOW, emptyList(), witnessKey) }
    titanCheckThrows<IllegalArgumentException>("negative sequence rejected") { factory.create(TITAN_DEVICE_ID, -2L, TITAN_NOW, emptyList(), witnessKey) }
    titanCheckThrows<IllegalArgumentException>("timestamp zero rejected") { factory.create(TITAN_DEVICE_ID, 1L, 0L, emptyList(), witnessKey) }
    val tooManyRows = (0 until TitanWitnessCheckpointFactory.MAX_ROWS + 1).map { index ->
        LedgerRow(TITAN_NOW + index, "titan-fim", "row $index")
    }
    titanCheckThrows<IllegalArgumentException>("too many rows rejected on create") { factory.create(TITAN_DEVICE_ID, 1L, TITAN_NOW, tooManyRows, witnessKey) }
    titanCheckThrows<IllegalArgumentException>("too many rows rejected on digest") { factory.ledgerDigest(tooManyRows) }
    titanCheckEquals(factory.ledgerDigest(tooManyRows.take(200)).length, 64, "200 rows accepted")
    val checkpoint = factory.create(TITAN_DEVICE_ID, 1L, TITAN_NOW, listOf(ledgerRow1), witnessKey)
    titanCheckEquals(checkpoint.ledgerDigestHex.length, 64, "digest field length")
    titanCheckEquals(checkpoint.macHex.length, 64, "mac field length")
    titanCheckTrue(factory.verify(checkpoint, TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey), "baseline verify")
    titanCheckTrue(!factory.verify(checkpoint, "not-a-device", listOf(ledgerRow1), witnessKey), "verify invalid device fails closed")
    titanCheckTrue(!factory.verify(checkpoint, TITAN_DEVICE_ID, tooManyRows, witnessKey), "verify too many rows fails closed")
    titanCheckThrows<IllegalArgumentException>("witness model validates sequence") {
        titanCheckTrue(!factory.verify(checkpoint.copy(sequence = 0L), TITAN_DEVICE_ID, listOf(ledgerRow1), witnessKey), "unreachable")
    }
}


internal fun registerFimWitnessTests() {
    titanTest("fim: first-run baseline creation + unreadable", ::testFimBaselineCreation)
    titanTest("fim: delta new/modified/match/retained/missing", ::testFimDelta)
    titanTest("fim: caps, dedupe, bounds, determinism, clock", ::testFimBounds)
    titanTest("witness: canonical KAT, create, verify, tamper", ::testWitness)
    titanTest("witness: validation and fail-closed verify", ::testWitnessValidation)
}
