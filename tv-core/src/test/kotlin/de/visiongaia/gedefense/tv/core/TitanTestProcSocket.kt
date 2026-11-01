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

// --- proc parser tests -------------------------------------------------------------------------

private fun testProcAddresses() {
    val parser = ProcNetParser()
    val v4 = listOf(
        "0100007F" to "127.0.0.1", "00000000" to "0.0.0.0", "0101A8C0" to "192.168.1.1",
        "08080808" to "8.8.8.8", "FFFFFFFF" to "255.255.255.255", "2D00000A" to "10.0.0.45",
    )
    v4.forEach { (hex, expected) ->
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP, hex), expected, "tcp ipv4 $hex")
        titanCheckEquals(parser.decodeAddress(SocketProtocol.UDP, hex), expected, "udp ipv4 $hex")
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP6, hex), null, "tcp6 rejects ipv4 width $hex")
    }
    titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP, "0100007f"), "127.0.0.1", "lowercase ipv4")
    val v6 = listOf(
        "00000000000000000000000001000000" to "::1",
        "00000000000000000000000000000000" to "::",
        "0000000000000000FFFF00000100007F" to "::ffff:7f00:1",
        "B80D0120000000000000000001000000" to "2001:db8::1",
        "B80D0120000000000000000000000000" to "2001:db8::",
    )
    v6.forEach { (hex, expected) ->
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP6, hex), expected, "tcp6 $hex")
        titanCheckEquals(parser.decodeAddress(SocketProtocol.UDP6, hex), expected, "udp6 $hex")
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP, hex), null, "tcp rejects ipv6 width $hex")
    }
    listOf("0100007", "0100007FF", "", "0100007G", "0100007g", "0100 07F").forEach { hex ->
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP, hex), null, "invalid ipv4 '$hex'")
    }
    listOf("", "0".repeat(31), "0".repeat(33), "G".repeat(32)).forEach { hex ->
        titanCheckEquals(parser.decodeAddress(SocketProtocol.TCP6, hex), null, "invalid ipv6 length/nibbles")
    }
}

private fun testProcStates() {
    val parser = ProcNetParser()
    val expected = linkedMapOf(
        "01" to SocketState.ESTABLISHED, "02" to SocketState.SYN_SENT, "03" to SocketState.SYN_RECV,
        "04" to SocketState.FIN_WAIT1, "05" to SocketState.FIN_WAIT2, "06" to SocketState.TIME_WAIT,
        "07" to SocketState.CLOSE, "08" to SocketState.CLOSE_WAIT, "09" to SocketState.LAST_ACK,
        "0A" to SocketState.LISTEN, "0B" to SocketState.CLOSING,
    )
    expected.forEach { (hex, state) ->
        titanCheckEquals(parser.decodeState(hex), state, "state $hex")
        titanCheckEquals(parser.decodeState(hex.lowercase()), state, "state lower ${hex.lowercase()}")
    }
    listOf("0C", "0D", "00", "FF", "10", "zz", "", "0", "1A", "100").forEach { raw ->
        titanCheckEquals(parser.decodeState(raw), SocketState.UNKNOWN, "unknown state '$raw'")
    }
    titanCheckEquals(expected.values.count { state -> state.isConnected }, 7, "connected state count")
    titanCheckEquals(expected.values.count { state -> state == SocketState.LISTEN }, 1, "listen state count")
    titanCheckEquals(ProcNetParser.DEFAULT_ROW_CAP, 4_096, "default row cap")
    titanCheckEquals(ProcNetParser.MAX_ROW_CAP, 65_536, "max row cap")
    titanCheckEquals(
        ProcNetParser.PROTOCOL_ORDER,
        listOf(SocketProtocol.TCP, SocketProtocol.TCP6, SocketProtocol.UDP, SocketProtocol.UDP6),
        "protocol order",
    )
}

private fun testProcRows() {
    val parser = ProcNetParser()
    val header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode"
    val listenRow = "   0: 00000000:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 11111 1 0 0 0"
    val establishedRow = "   1: 0A00000A:9C40 2000002D:01BB 01 00000000:00000000 00:00000000 00000000 10050        0 22222 1 0 0 0"
    val rows = parser.parse(SocketProtocol.TCP, "$header\n$listenRow\n$establishedRow\n")
    titanCheckEquals(rows.size, 2, "two decoded rows")
    titanCheckEquals(rows[0].state, SocketState.LISTEN, "listen state")
    titanCheckEquals(rows[0].localAddress, "0.0.0.0", "listen local")
    titanCheckEquals(rows[0].localPort, 8_080, "listen local port")
    titanCheckEquals(rows[0].uid, 0, "listen uid")
    titanCheckEquals(rows[0].inode, 11_111L, "listen inode")
    titanCheckEquals(rows[1].localAddress, "10.0.0.10", "established local")
    titanCheckEquals(rows[1].localPort, 40_000, "established local port")
    titanCheckEquals(rows[1].remoteAddress, "45.0.0.32", "established remote")
    titanCheckEquals(rows[1].remotePort, 443, "established remote port")
    titanCheckEquals(rows[1].state, SocketState.ESTABLISHED, "established state")
    titanCheckEquals(rows[1].uid, 10_050, "established uid")
    titanCheckEquals(rows[1].inode, 22_222L, "established inode")
    titanCheckEquals(rows[0].protocol, SocketProtocol.TCP, "protocol preserved")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, "$header\r\n$listenRow\r\n").size, 1, "CRLF tolerated")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, "$header\n${listenRow.replace(" ", "\t")}\n").size, 1, "tabs tolerated")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, "$header\n$listenRow".replace(" ", "  ")).size, 1, "multi spaces tolerated")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, header).size, 0, "header only is empty")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, "").size, 0, "empty content")
    val unknownState = "   0: 00000000:1F90 00000000:0000 0C 00000000:00000000 00:00000000 00000000     0        0 33333 1 0"
    val stateRow = parser.parse(SocketProtocol.TCP, "$header\n$unknownState\n").single()
    titanCheckEquals(stateRow.state, SocketState.UNKNOWN, "unknown st still decodes row")
    titanCheckEquals(stateRow.inode, 33_333L, "unknown state inode")
    val malformed = listOf(
        "", "garbage", "0: ZZZZ:1F90 00000000:0000 01 0:0 0:0 0 1000 0 1",
        "0: 0100007F:1F90 ZZZZZZZZ:0000 01 0:0 0:0 0 1000 0 1",
        "0: 0100007F:1F90 00000000:0000 01 0:0 0:0 0 abc 0 1",
        "0: 0100007F:1F90 00000000:0000 01 0:0 0:0 0 3000000000 0 1",
        "0: 0100007F:1F90 00000000:0000 01 0:0 0:0 0 1000 0 -1",
        "0: 0100007F:1F90 00000000:0000 01 0:0 0:0 0 1000 0 abc",
        "0: 0100007F:1F90 00000000:0000",
        "0: 0100007F:1F900 00000000:0000 01 0:0 0:0 0 1000 0 1",
        "0: 0100007F:1F9Z 00000000:0000 01 0:0 0:0 0 1000 0 1",
        "0: 0100007F1F90 00000000:0000 01 0:0 0:0 0 1000 0 1",
        "0: 0100007:1F90 00000000:0000 01 0:0 0:0 0 1000 0 1",
    )
    malformed.forEach { badRow ->
        titanCheckEquals(parser.parse(SocketProtocol.TCP, "$header\n$badRow\n$listenRow").size, 1, "malformed skipped: '$badRow'")
    }
    val capContent = "$header\n$listenRow\n$establishedRow\n$unknownState\n"
    titanCheckEquals(parser.parse(SocketProtocol.TCP, capContent, cap = 2).size, 2, "cap 2")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, capContent, cap = 1).size, 1, "cap 1")
    titanCheckEquals(parser.parse(SocketProtocol.TCP, capContent, cap = 0).size, 0, "cap 0")
    titanCheckThrows<IllegalArgumentException>("negative cap rejected") { parser.parse(SocketProtocol.TCP, capContent, cap = -1) }
    titanCheckThrows<IllegalArgumentException>("cap above maximum rejected") {
        parser.parse(SocketProtocol.TCP, capContent, cap = ProcNetParser.MAX_ROW_CAP + 1)
    }
    val overScan = buildString {
        append(header).append('\n')
        repeat(ProcNetParser.MAX_SCAN_LINES + 1) { append("junk\n") }
        append(listenRow)
    }
    titanCheckEquals(parser.parse(SocketProtocol.TCP, overScan).size, 0, "line scan is bounded")
    val v6Row = "   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A " +
        "00000000:00000000 00:00000000 00000000     0        0 44444 1 0"
    val v6Rows = parser.parse(SocketProtocol.TCP6, "$header\n$v6Row\n")
    titanCheckEquals(v6Rows.single().localAddress, "::1", "tcp6 local address")
    titanCheckEquals(v6Rows.single().localPort, 8_080, "tcp6 local port")
    val tables = linkedMapOf(
        SocketProtocol.UDP6 to "$header\n${procRowFor(SocketProtocol.UDP6, "1F93", "44444")}",
        SocketProtocol.TCP to "$header\n${procRowFor(SocketProtocol.TCP, "1F90", "11111")}",
        SocketProtocol.UDP to "$header\n${procRowFor(SocketProtocol.UDP, "1F92", "33333")}",
        SocketProtocol.TCP6 to "$header\n${procRowFor(SocketProtocol.TCP6, "1F91", "22222")}",
    )
    val all = parser.parseAll(tables)
    titanCheckEquals(
        all.map { socket -> socket.protocol },
        listOf(SocketProtocol.TCP, SocketProtocol.TCP6, SocketProtocol.UDP, SocketProtocol.UDP6),
        "parseAll deterministic protocol order",
    )
    titanCheckEquals(all.map { socket -> socket.localPort }, listOf(8_080, 8_081, 8_082, 8_083), "parseAll ports")
    titanCheckEquals(parser.parseAll(mapOf(SocketProtocol.TCP to "$header\n${procRowFor(SocketProtocol.TCP, "1F90", "1")}")).size, 1, "parseAll missing tables")
    titanCheckEquals(parser.parseAll(emptyMap()).size, 0, "parseAll empty map")
    titanCheckThrows<IllegalArgumentException>("parseAll invalid cap") { parser.parseAll(tables, cap = -5) }
}

/** One header-compatible synthetic kernel row. */
private fun procRowFor(protocol: SocketProtocol, portHex: String, inode: String): String {
    val local = if (protocol.isV6) "00000000000000000000000001000000" else "0100007F"
    val remote = if (protocol.isV6) "00000000000000000000000000000000" else "00000000"
    return "   0: $local:$portHex $remote:0000 0A 00000000:00000000 00:00000000 00000000 10050 0 $inode 1 0"
}

// --- socket provenance tests -------------------------------------------------------------------

private fun testSocketClassification() {
    val engine = SocketProvenanceEngine()
    val empty = engine.analyze(emptyList(), emptyMap(), emptyMap(), emptyMap(), TITAN_NOW)
    titanCheckEquals(empty.observations, emptyList<SocketObservation>(), "empty observations")
    titanCheckEquals(empty.totalSockets, 0, "empty total sockets")
    titanCheckEquals(empty.attributableSockets, 0, "empty attributable")
    titanCheckEquals(empty.suspiciousCount, 0, "empty suspicious")
    titanCheckEquals(empty.capturedAtMillis, TITAN_NOW, "empty capture time")
    titanCheckEquals(empty.visibility, DataVisibility.PARTIAL, "empty visibility")
    titanCheckEquals(empty.truncated, false, "empty not truncated")
    titanCheckEquals(empty.note, null, "empty note")
    val attributed = engine.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(attributed.observations.size, 1, "attributed observation count")
    val observation = attributed.observations.single()
    titanCheckEquals(observation.remoteEndpoint, "45.33.32.7:443", "remote endpoint")
    titanCheckEquals(observation.protocol, SocketProtocol.TCP, "observation protocol")
    titanCheckEquals(observation.state, SocketState.ESTABLISHED, "observation state")
    titanCheckEquals(observation.pid, 1_000, "observation pid")
    titanCheckEquals(observation.uid, 10_050, "observation uid")
    titanCheckEquals(observation.packageName, "com.example.app", "observation package")
    titanCheckEquals(observation.risk, SocketRisk.NONE, "attributed risk")
    titanCheckEquals(observation.severity, null, "attributed severity")
    titanCheckEquals(observation.threatFeedIds, emptyList<String>(), "attributed feeds")
    titanCheckEquals(observation.observedAtMillis, TITAN_NOW, "observation timestamp")
    titanCheckEquals(attributed.totalSockets, 1, "attributed total")
    titanCheckEquals(attributed.attributableSockets, 1, "attributed attributable")
    titanCheckEquals(attributed.suspiciousCount, 0, "attributed suspicious")
    titanCheckEquals(attributed.visibility, DataVisibility.FULL, "attributed visibility")
    val unknownPid = engine.analyze(listOf(rawSocket(99L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(unknownPid.observations.single().risk, SocketRisk.UNATTRIBUTED, "unknown pid risk")
    titanCheckEquals(unknownPid.observations.single().severity, Severity.MEDIUM, "unknown pid severity")
    titanCheckEquals(unknownPid.observations.single().pid, null, "unknown pid")
    titanCheckEquals(unknownPid.visibility, DataVisibility.FULL, "unknown pid visibility through uid attribution")
    val unknownPackage = engine.analyze(listOf(rawSocket(1L, uid = 999_999)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(unknownPackage.observations.single().risk, SocketRisk.UNATTRIBUTED, "unknown package risk")
    titanCheckEquals(unknownPackage.observations.single().packageName, null, "unknown package")
    val fallback = engine.analyze(listOf(rawSocket(2L, uid = 0)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(fallback.observations.single().uid, 10_100, "uid fallback from process")
    titanCheckEquals(fallback.observations.single().packageName, "com.example.two", "fallback package")
    val primary = engine.analyze(listOf(rawSocket(1L, uid = 10_100)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(primary.observations.single().uid, 10_100, "socket uid is primary")
    titanCheckEquals(primary.observations.single().packageName, "com.example.two", "primary package")
    val listeners = engine.analyze(
        listOf(
            rawSocket(1L, state = SocketState.LISTEN, localPort = 8_080, remoteAddress = "0.0.0.0", remotePort = 0),
            rawSocket(2L, state = SocketState.LISTEN, localPort = 5_555, remoteAddress = "0.0.0.0", remotePort = 0, uid = 0),
        ),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(listeners.observations.size, 1, "only ADB listener observed")
    titanCheckEquals(listeners.observations.single().risk, SocketRisk.ADB_EXPOSED, "ADB risk")
    titanCheckEquals(listeners.observations.single().severity, Severity.HIGH, "ADB severity")
    titanCheckEquals(listeners.observations.single().remoteEndpoint, "0.0.0.0:0", "ADB endpoint")
    val skipped = engine.analyze(
        listOf(rawSocket(1L, remoteAddress = "0.0.0.0", remotePort = 0)),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(skipped.observations, emptyList<SocketObservation>(), "unspecified remote skipped")
    titanCheckEquals(skipped.totalSockets, 0, "unspecified remote total")
    val threatEngine = SocketProvenanceEngine(threatIndexProvider = { titanC2Index("45.33.32.0/24") })
    val threat = threatEngine.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(threat.observations.single().risk, SocketRisk.THREAT_FEED_MATCH, "threat risk")
    titanCheckEquals(threat.observations.single().severity, Severity.CRITICAL, "threat severity")
    titanCheckEquals(threat.observations.single().threatFeedIds, listOf("feodo"), "threat feed ids")
    titanCheckEquals(threat.suspiciousCount, 1, "threat suspicious count")
    val threatUnattributed = threatEngine.analyze(listOf(rawSocket(99L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(threatUnattributed.observations.single().risk, SocketRisk.THREAT_FEED_MATCH, "threat beats unattributed")
    titanCheckEquals(threatUnattributed.observations.single().severity, Severity.CRITICAL, "threat unattributed severity")
    val threatProvider = SocketProvenanceEngine(threatIndexProvider = { ThreatIndex.empty() })
    titanCheckEquals(threatProvider.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW).observations.single().risk, SocketRisk.NONE, "empty provider risk")
    val adbThreat = threatEngine.analyze(
        listOf(rawSocket(1L, localPort = 5_555, remoteAddress = "8.8.8.8", remotePort = 53)),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(adbThreat.observations.single().risk, SocketRisk.ADB_EXPOSED, "ADB risk without feed match")
    titanCheckEquals(adbThreat.observations.single().severity, Severity.HIGH, "ADB severity without feed match")
}

private fun testSocketBounds() {
    val threatEngine = SocketProvenanceEngine(threatIndexProvider = { titanC2Index("45.33.32.0/24") })
    val ordered = threatEngine.analyze(
        listOf(
            rawSocket(1L, remoteAddress = "8.8.8.8"),
            rawSocket(99L, remoteAddress = "9.9.9.9", remotePort = 53),
            rawSocket(10L, remoteAddress = "45.33.32.9"),
            rawSocket(11L, state = SocketState.LISTEN, localPort = 5_555, remoteAddress = "0.0.0.0", remotePort = 0, uid = 0),
        ),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(
        ordered.observations.map { observation -> observation.remoteEndpoint },
        listOf("45.33.32.9:443", "0.0.0.0:0", "9.9.9.9:53", "8.8.8.8:443"),
        "threat-first deterministic ordering",
    )
    titanCheckEquals(
        ordered.observations.map { observation -> observation.risk },
        listOf(SocketRisk.THREAT_FEED_MATCH, SocketRisk.ADB_EXPOSED, SocketRisk.UNATTRIBUTED, SocketRisk.NONE),
        "risk ordering",
    )
    val engine = SocketProvenanceEngine()
    val input = listOf(rawSocket(1L), rawSocket(2L), rawSocket(99L))
    titanCheckEquals(
        engine.analyze(input, inodeToPid, uidByPid, packagesByUid, TITAN_NOW),
        SocketProvenanceEngine().analyze(input, inodeToPid, uidByPid, packagesByUid, TITAN_NOW),
        "deterministic across instances",
    )
    titanCheckEquals(
        engine.analyze(input, LinkedHashMap(inodeToPid), LinkedHashMap(uidByPid.entries.reversed().associate { entry -> entry.key to entry.value }), packagesByUid, TITAN_NOW),
        engine.analyze(input, inodeToPid, uidByPid, packagesByUid, TITAN_NOW),
        "map iteration order irrelevant",
    )
    val socketCapped = SocketProvenanceEngine(config = SocketProvenanceConfig(maxSockets = 2))
    val capped = socketCapped.analyze(input, inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(capped.totalSockets, 2, "maxSockets cap")
    titanCheckEquals(capped.truncated, true, "maxSockets truncation")
    val observationCap = SocketProvenanceEngine(config = SocketProvenanceConfig(maxObservations = 1))
    val mixed = observationCap.analyze(
        listOf(rawSocket(1L), rawSocket(77L, remoteAddress = "9.9.9.9", uid = 999_999), rawSocket(78L, remoteAddress = "9.9.9.8", uid = 999_999)),
        inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(mixed.observations.size, 1, "observation cap applied")
    titanCheckEquals(mixed.totalSockets, 3, "observation cap total")
    titanCheckEquals(mixed.observations.single().risk, SocketRisk.UNATTRIBUTED, "observation cap keeps risk order")
    titanCheckEquals(mixed.visibility, DataVisibility.PARTIAL, "observation cap visibility")
    titanCheckEquals(mixed.note, MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED), "observation cap note")
    titanCheckEquals(mixed.truncated, true, "observation cap truncated")
    val fullTruncated = observationCap.analyze(listOf(rawSocket(1L), rawSocket(2L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(fullTruncated.observations.size, 1, "truncated size")
    titanCheckEquals(fullTruncated.visibility, DataVisibility.PARTIAL, "truncated pass is never FULL")
    titanCheckEquals(fullTruncated.note, MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED), "truncated pass carries the limited note")
    titanCheckEquals(fullTruncated.truncated, true, "truncated pass flagged")
    val budget = SocketProvenanceEngine(config = SocketProvenanceConfig(maxProcessEntries = 1))
    val budgetSnapshot = budget.analyze(listOf(rawSocket(1L), rawSocket(2L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW)
    titanCheckEquals(budgetSnapshot.observations.count { observation -> observation.risk == SocketRisk.UNATTRIBUTED }, 1, "process budget unattributed")
    titanCheckEquals(budgetSnapshot.observations.count { observation -> observation.pid == null }, 1, "process budget pid missing")
    titanCheckEquals(budgetSnapshot.truncated, true, "process budget truncation")
    val clamped = engine.analyze(listOf(rawSocket(1L)), inodeToPid, uidByPid, packagesByUid, 0L)
    titanCheckEquals(clamped.capturedAtMillis, 1L, "non-positive clock clamps")
    titanCheckEquals(clamped.observations.single().observedAtMillis, 1L, "observation clock clamps")
    val invalidPid = engine.analyze(
        listOf(rawSocket(9L)),
        mapOf(9L to SocketObservation.MAX_PID + 1), emptyMap(), emptyMap(), TITAN_NOW,
    )
    titanCheckEquals(invalidPid.observations.single().pid, null, "out-of-range pid rejected")
    titanCheckEquals(invalidPid.observations.single().risk, SocketRisk.UNATTRIBUTED, "out-of-range pid unattributed")
    // F-11: UID -> package attribution must never guess when a UID is shared by several packages.
    val zeroPackages = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid, mapOf(10_050 to emptyList()), TITAN_NOW,
    )
    titanCheckEquals(zeroPackages.observations.single().packageName, null, "zero visible packages stays unattributed")
    titanCheckEquals(zeroPackages.observations.single().risk, SocketRisk.UNATTRIBUTED, "zero packages unattributed risk")
    titanCheckEquals(zeroPackages.attributableSockets, 0, "zero packages attributable count")
    val sharedUid = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid,
        mapOf(10_050 to listOf("com.z.app", "com.a.app")), TITAN_NOW,
    )
    titanCheckEquals(sharedUid.observations.single().packageName, null, "shared uid is not guessed")
    titanCheckEquals(sharedUid.observations.single().risk, SocketRisk.UNATTRIBUTED, "shared uid unattributed risk")
    titanCheckEquals(sharedUid.observations.single().severity, Severity.MEDIUM, "shared uid medium severity")
    titanCheckEquals(sharedUid.attributableSockets, 0, "shared uid attributable count")
    titanCheckEquals(sharedUid.visibility, DataVisibility.PARTIAL, "shared uid visibility is partial")
    titanCheckEquals(
        sharedUid,
        engine.analyze(
            listOf(rawSocket(1L)), inodeToPid, uidByPid,
            mapOf(10_050 to listOf("com.z.app", "com.a.app")), TITAN_NOW,
        ),
        "shared uid analysis deterministic",
    )
    val reverseShared = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid,
        mapOf(10_050 to listOf("com.a.app", "com.z.app")), TITAN_NOW,
    )
    titanCheckEquals(reverseShared.observations.single().packageName, null, "ambiguity independent of candidate order")
    val duplicateOnly = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid,
        mapOf(10_050 to listOf("com.a.app", "com.a.app")), TITAN_NOW,
    )
    titanCheckEquals(duplicateOnly.observations.single().packageName, "com.a.app", "duplicate same package is one package")
    val invalidExtra = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid,
        mapOf(10_050 to listOf("com.a.app", "bad package")), TITAN_NOW,
    )
    titanCheckEquals(invalidExtra.observations.single().packageName, "com.a.app", "invalid candidate is not a second package")
    val onlyInvalid = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid, mapOf(10_050 to listOf("bad package")), TITAN_NOW,
    )
    titanCheckEquals(onlyInvalid.observations.single().packageName, null, "invalid package candidates ignored")
    // The candidate window is bounded (64); exceeding it can never prove uniqueness, so no guess.
    val boundedWindow = engine.analyze(
        listOf(rawSocket(1L)), inodeToPid, uidByPid,
        mapOf(10_050 to List(64) { "com.a.app" } + "com.z.app"), TITAN_NOW,
    )
    titanCheckEquals(boundedWindow.observations.single().packageName, null, "bounded candidate window never guesses")
    val ambiguousPair = engine.analyze(
        listOf(rawSocket(1L, remoteAddress = "9.9.9.9"), rawSocket(2L, remoteAddress = "9.9.9.8")),
        inodeToPid, uidByPid,
        mapOf(10_050 to listOf("com.z.app", "com.a.app"), 10_100 to listOf("com.b.app", "com.c.app")), TITAN_NOW,
    )
    titanCheckEquals(
        ambiguousPair.observations.map { observation -> observation.remoteEndpoint },
        listOf("9.9.9.8:443", "9.9.9.9:443"),
        "ambiguous rows keep deterministic endpoint ordering",
    )
    // Single-package attribution ratio/visibility math is unchanged by the ambiguity rule.
    val singlePackagePair = engine.analyze(
        listOf(rawSocket(1L), rawSocket(2L)), inodeToPid, uidByPid, packagesByUid, TITAN_NOW,
    )
    titanCheckEquals(singlePackagePair.attributableSockets, 2, "single package attribution count")
    titanCheckEquals(singlePackagePair.visibility, DataVisibility.FULL, "single package visibility ratio")
    listOf(
        "empty" to SocketSnapshot.empty(TITAN_NOW, DataVisibility.PARTIAL),
        "ambiguous" to sharedUid,
        "mixed" to mixed,
        "budget" to budgetSnapshot,
        "single-package" to singlePackagePair,
    ).forEach { (label, snapshot) ->
        titanCheckTrue(snapshot.attributableSockets <= snapshot.totalSockets, "$label attributable bound")
        titanCheckTrue(snapshot.suspiciousCount <= snapshot.totalSockets, "$label suspicious bound")
        titanCheckTrue(snapshot.observations.size <= SocketSnapshot.MAX_OBSERVATIONS, "$label observation bound")
        titanCheckTrue(snapshot.capturedAtMillis > 0L, "$label capture positive")
    }
}


internal fun registerProcSocketTests() {
    titanTest("proc: address decoding IPv4/IPv6 little-endian + invalid", ::testProcAddresses)
    titanTest("proc: state map coverage", ::testProcStates)
    titanTest("proc: table rows CRLF/tabs/malformed/cap/parseAll", ::testProcRows)
    titanTest("socket: empty, attribution, uid fallback, ADB, threat", ::testSocketClassification)
    titanTest("socket: ordering, caps, truncation, provider, invariants", ::testSocketBounds)
}
