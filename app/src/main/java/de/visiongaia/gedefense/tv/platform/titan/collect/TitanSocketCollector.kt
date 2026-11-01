package de.visiongaia.gedefense.tv.platform.titan.collect

import android.content.Context
import android.os.Process
import android.system.Os
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.model.RawSocket
import de.visiongaia.gedefense.tv.core.titan.model.SocketObservation
import de.visiongaia.gedefense.tv.core.titan.model.SocketProtocol
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys
import de.visiongaia.gedefense.tv.core.titan.proc.ProcNetParser
import de.visiongaia.gedefense.tv.core.titan.proc.SocketProvenanceEngine
import de.visiongaia.gedefense.tv.core.titan.response.TitanCommandFactory
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanShell
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream

/**
 * Passive socket-provenance collector of the Titan Engine.
 *
 * Honest gating first: without [TitanCapability.SOCKET_PROVENANCE] in the effective capability set
 * the collector returns an explicit PARTIAL empty snapshot with a catalog note - never a green "clean"
 * result. Data is read only through the confirmed root channel ([TitanShell] + the allow-listed
 * `readProcTable` command). A direct `File` read of a `/proc/net` table is attempted only when the
 * root channel actually failed and the file is readable by this process; such a fallback is reported
 * as PARTIAL visibility because an unprivileged table read cannot prove complete coverage.
 *
 * All kernel content and shell output is treated as hostile: every table is byte-capped, parsed by the
 * bounded [ProcNetParser], and no parser exception can escape [collect]. Process attribution is
 * UID-first (`PackageManager.getPackagesForUid`); the inode->PID join is best-effort and only uses
 * `/proc` entries this process can actually read (own fds plus directly readable PIDs), so a missing
 * PID is honest "app unknown", not a verdict.
 *
 * Threading: [collect] performs blocking file/package-manager/proc reads and MUST run on a background
 * worker (the TitanController scan executor), never on the UI thread.
 *
 * @param context application context (only `PackageManager` is used from it).
 * @param shellProvider returns the confirmed shell channel, or `null` when it is unavailable.
 * @param threatIndexProvider returns the validated local threat index; failures degrade to empty.
 */
class TitanSocketCollector(
    context: Context,
    private val shellProvider: () -> TitanShell?,
    threatIndexProvider: () -> ThreatIndex,
) {
    private val appContext: Context = context.applicationContext ?: context
    private val parser = ProcNetParser()
    private val engine = SocketProvenanceEngine(
        threatIndexProvider = {
            try {
                threatIndexProvider()
            } catch (_: Throwable) {
                ThreatIndex.empty()
            }
        },
    )

    /**
     * Runs one bounded socket pass. Never throws; every failure path returns a PARTIAL empty snapshot
     * with the socket-limited note.
     */
    fun collect(privilege: TitanPrivilegeSnapshot, nowMillis: Long): SocketSnapshot {
        val now = nowMillis.coerceAtLeast(1L)
        return try {
            collectInternal(privilege, now)
        } catch (_: Throwable) {
            unavailable(now)
        }
    }

    private fun collectInternal(privilege: TitanPrivilegeSnapshot, now: Long): SocketSnapshot {
        if (TitanCapability.SOCKET_PROVENANCE !in TitanCapabilityMatrix.effectiveCapabilities(privilege)) {
            return unavailable(now)
        }
        val shell = try {
            shellProvider()
        } catch (_: Throwable) {
            null
        }
        val read = readTables(shell)
        if (read.tables.isEmpty()) return unavailable(now)
        // A parser failure means the table contents are not trustworthy: it must never degrade into a
        // clean-looking "no connections" empty snapshot, so it is reported as explicitly limited.
        val sockets = try {
            parser.parseAll(read.tables)
        } catch (_: Throwable) {
            return SocketSnapshot.empty(
                now,
                DataVisibility.PARTIAL,
                if (read.truncated) truncatedNote() else limitedNote(),
            )
        }
        if (sockets.isEmpty()) {
            // A completely read table set with zero rows is a real "no sockets" observation; an
            // incomplete read is explicitly labelled as limited instead.
            val note = if (read.incomplete || read.usedFallback) limitedNote() else null
            return SocketSnapshot.empty(now, DataVisibility.PARTIAL, note)
        }
        val processes = scanProcesses()
        val packagesByUid = resolvePackages(sockets)
        var snapshot = engine.analyze(
            sockets = sockets,
            inodeToPid = processes.inodeToPid,
            uidByPid = processes.uidByPid,
            packagesByUid = packagesByUid,
            nowMillis = now,
        )
        // The engine can only judge what it received: an incomplete/unprivileged read must downgrade
        // a FULL result and add an explicit note.
        if (read.incomplete || read.usedFallback) {
            val visibility = if (snapshot.visibility == DataVisibility.FULL) DataVisibility.PARTIAL else snapshot.visibility
            snapshot = snapshot.copy(
                visibility = visibility,
                truncated = snapshot.truncated || read.truncated,
                note = snapshot.note ?: if (read.truncated) truncatedNote() else limitedNote(),
            )
        }
        return snapshot
    }

    // ------------------------------------------------------------------ table reading

    private data class TableRead(
        val tables: Map<SocketProtocol, String>,
        val incomplete: Boolean,
        val usedFallback: Boolean,
        val truncated: Boolean,
    )

    private fun readTables(shell: TitanShell?): TableRead {
        val tables = LinkedHashMap<SocketProtocol, String>()
        var incomplete = false
        var usedFallback = false
        var truncated = false
        for (protocol in ProcNetParser.PROTOCOL_ORDER) {
            val path = PROC_NET_DIR + protocol.procFile
            var content: String? = null
            if (shell != null) {
                content = readThroughShell(shell, path)
            }
            if (content == null) {
                // Root channel failed: only claim what this process can really read.
                content = readDirect(path)
                if (content != null) {
                    usedFallback = true
                    if (content.length >= MAX_TABLE_BYTES) truncated = true
                }
            }
            if (content == null) {
                incomplete = true
            } else {
                tables[protocol] = content
            }
        }
        return TableRead(tables, incomplete = incomplete, usedFallback = usedFallback, truncated = truncated)
    }

    private fun readThroughShell(shell: TitanShell, path: String): String? {
        val command = try {
            TitanCommandFactory.readProcTable(path)
        } catch (_: Throwable) {
            return null
        }
        return try {
            shell.readTable(command, MAX_TABLE_BYTES)
        } catch (_: Throwable) {
            null
        }
    }

    /** Bounded direct read used only as an honest fallback; `null` when the file is not readable. */
    private fun readDirect(path: String): String? {
        return try {
            val file = File(path)
            if (!file.isFile || !file.canRead()) return null
            val length = file.length()
            if (length > MAX_TABLE_BYTES) return null
            FileInputStream(file).use { stream ->
                val buffer = ByteArray(READ_CHUNK_BYTES)
                val output = ByteArrayOutputStream(INITIAL_BUFFER_BYTES)
                var total = 0
                while (total < MAX_TABLE_BYTES) {
                    val read = stream.read(buffer)
                    if (read <= 0) break
                    val allowed = minOf(read, MAX_TABLE_BYTES - total)
                    output.write(buffer, 0, allowed)
                    total += allowed
                    if (allowed < read) break
                }
                String(output.toByteArray(), Charsets.UTF_8)
            }
        } catch (_: Throwable) {
            null
        }
    }

    // -------------------------------------------------------------- process attribution

    private data class ProcessMaps(val inodeToPid: Map<Long, Int>, val uidByPid: Map<Int, Int>)

    /**
     * Best-effort inode->PID and PID->UID maps. Only readable `/proc` entries are used: own fds first
     * (always readable), then a bounded alphabetical scan of visible PIDs. The whole scan has a wall
     * clock budget, so a hostile/busy device cannot stall the collector.
     */
    private fun scanProcesses(): ProcessMaps {
        val inodeToPid = HashMap<Long, Int>(64)
        val uidByPid = HashMap<Int, Int>(32)
        try {
            val deadline = System.nanoTime() + PROCESS_SCAN_BUDGET_NANOS
            val ownPid = Process.myPid()
            val ownUid = Process.myUid()
            if (ownPid in 1..SocketObservation.MAX_PID && ownUid in 0..RawSocket.MAX_UID) {
                uidByPid[ownPid] = ownUid
            }
            var links = scanFdDirectory(OWN_FD_DIR, ownPid, MAX_OWN_FDS, inodeToPid, deadline)
            for (pid in visiblePids(ownPid)) {
                if (links >= MAX_TOTAL_FD_LINKS || System.nanoTime() - deadline > 0L) break
                if (inodeToPid.size >= MAX_INODE_ENTRIES) break
                val uid = readPidUid(pid) ?: continue
                uidByPid[pid] = uid
                links += scanFdDirectory(PROC_DIR + pid + "/fd", pid, MAX_FDS_PER_PID, inodeToPid, deadline)
            }
        } catch (_: Throwable) {
            // Attribution is an enrichment: an unreadable /proc stays "app unknown", never a crash.
        }
        return ProcessMaps(inodeToPid, uidByPid)
    }

    private fun visiblePids(ownPid: Int): List<Int> {
        val entries = try {
            File(PROC_DIR).list()
        } catch (_: Throwable) {
            null
        } ?: return emptyList()
        val pids = ArrayList<Int>(32)
        for (name in entries) {
            if (pids.size >= MAX_VISIBLE_PIDS) break
            if (name.length !in 1..7 || !name.all { it.isDigit() }) continue
            val pid = name.toIntOrNull() ?: continue
            if (pid !in 1..SocketObservation.MAX_PID || pid == ownPid) continue
            pids += pid
        }
        pids.sort()
        return pids
    }

    /**
     * Maps socket inodes of one `/proc/<pid>/fd` directory to [pid].
     *
     * @return number of fd entries attempted (the caller's total-work bound).
     */
    private fun scanFdDirectory(
        directory: String,
        pid: Int,
        maxEntries: Int,
        sink: MutableMap<Long, Int>,
        deadline: Long,
    ): Int {
        if (pid !in 1..SocketObservation.MAX_PID) return 0
        val names = try {
            File(directory).list()
        } catch (_: Throwable) {
            null
        } ?: return 0
        var attempts = 0
        for (name in names) {
            if (attempts >= maxEntries || sink.size >= MAX_INODE_ENTRIES) break
            if (attempts % DEADLINE_CHECK_INTERVAL == 0 && System.nanoTime() - deadline > 0L) break
            attempts += 1
            val link = try {
                Os.readlink("$directory/$name")
            } catch (_: Throwable) {
                null
            } ?: continue
            val inode = parseSocketInode(link) ?: continue
            sink.putIfAbsent(inode, pid)
        }
        return attempts
    }

    private fun readPidUid(pid: Int): Int? {
        val status = readSmallFile(PROC_DIR + pid + "/status") ?: return null
        for (line in status.lineSequence()) {
            if (!line.startsWith(UID_PREFIX)) continue
            val token = line.substring(UID_PREFIX.length).trim().substringBefore(' ').substringBefore('\t')
            val uid = token.toIntOrNull() ?: return null
            return uid.takeIf { it in 0..RawSocket.MAX_UID }
        }
        return null
    }

    private fun parseSocketInode(link: String): Long? {
        if (!link.startsWith(SOCKET_PREFIX) || !link.endsWith("]")) return null
        val number = link.substring(SOCKET_PREFIX.length, link.length - 1)
        if (number.isEmpty() || number.length > 18 || !number.all { it.isDigit() }) return null
        return number.toLongOrNull()?.takeIf { it >= 0L }
    }

    private fun readSmallFile(path: String): String? {
        return try {
            val file = File(path)
            if (!file.isFile || !file.canRead()) return null
            FileInputStream(file).use { stream ->
                val buffer = ByteArray(MAX_STATUS_BYTES)
                var total = 0
                while (total < buffer.size) {
                    val read = stream.read(buffer, total, buffer.size - total)
                    if (read <= 0) break
                    total += read
                }
                String(buffer, 0, total, Charsets.UTF_8)
            }
        } catch (_: Throwable) {
            null
        }
    }

    // --------------------------------------------------------------- package resolution

    private fun resolvePackages(sockets: List<RawSocket>): Map<Int, List<String>> {
        val result = HashMap<Int, List<String>>(32)
        val uids = LinkedHashSet<Int>()
        for (socket in sockets) {
            if (uids.size >= MAX_PACKAGE_UIDS) break
            uids += socket.uid
        }
        val packageManager = try {
            appContext.packageManager
        } catch (_: Throwable) {
            return result
        }
        for (uid in uids) {
            val names: Array<String>? = try {
                packageManager.getPackagesForUid(uid)
            } catch (_: Throwable) {
                null
            }
            if (names == null) continue
            val valid = ArrayList<String>(names.size)
            for (name in names) {
                if (valid.size >= MAX_PACKAGES_PER_UID) break
                if (name.length !in 1..MAX_PACKAGE_NAME_LENGTH || !PACKAGE_PATTERN.matches(name)) continue
                if (valid.contains(name)) continue
                valid += name
            }
            if (valid.isNotEmpty()) result[uid] = valid.sorted()
        }
        return result
    }

    // ------------------------------------------------------------------------ helpers

    private fun unavailable(now: Long): SocketSnapshot =
        SocketSnapshot.empty(now, DataVisibility.PARTIAL, limitedNote())

    private fun limitedNote(): MessageRef = MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED)

    private fun truncatedNote(): MessageRef = MessageRef(TitanTextKeys.NOTE_SOCKET_TRUNCATED)

    private companion object {
        const val PROC_NET_DIR = "/proc/net/"
        const val PROC_DIR = "/proc/"
        const val OWN_FD_DIR = "/proc/self/fd"

        const val MAX_TABLE_BYTES = 256 * 1024
        const val INITIAL_BUFFER_BYTES = 16 * 1024
        const val READ_CHUNK_BYTES = 8 * 1024
        const val MAX_STATUS_BYTES = 4 * 1024

        const val MAX_OWN_FDS = 256
        const val MAX_FDS_PER_PID = 64
        const val MAX_VISIBLE_PIDS = 64
        const val MAX_TOTAL_FD_LINKS = 1_024
        const val MAX_INODE_ENTRIES = 4_096
        const val DEADLINE_CHECK_INTERVAL = 16
        const val PROCESS_SCAN_BUDGET_NANOS = 1_500_000_000L

        const val MAX_PACKAGE_UIDS = 256
        const val MAX_PACKAGES_PER_UID = 8
        const val MAX_PACKAGE_NAME_LENGTH = 256

        const val UID_PREFIX = "Uid:"
        const val SOCKET_PREFIX = "socket:["

        val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(\\.[A-Za-z0-9_]+){1,15}")
    }
}
