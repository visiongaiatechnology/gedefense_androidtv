package de.visiongaia.gedefense.tv.vpn

import android.content.Context
import android.os.ParcelFileDescriptor
import android.util.Log
import de.visiongaia.gedefense.mobile.core.IpAddress
import de.visiongaia.gedefense.mobile.core.IpPrefix
import de.visiongaia.gedefense.mobile.core.PrivacyAction
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.tv.core.model.TrafficAction
import de.visiongaia.gedefense.tv.core.model.TvPrivacyProfile
import de.visiongaia.gedefense.tv.data.TvSettingsStore
import de.visiongaia.gedefense.tv.traffic.TvTrafficStore
import java.io.BufferedReader
import java.io.FileInputStream
import java.io.InputStreamReader
import java.util.LinkedHashMap
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Reads the native GaiaNet telemetry channel and feeds the bounded [TvTrafficStore].
 *
 * Ported from the mobile dossier's `FullFlowTelemetryReader`: the line protocol is unchanged
 * (single tab-separated ASCII frames, 2..1024 bytes each). Packet blocks arrive as authoritative
 * native events; app ownership is resolved locally via [ConnectionOwnerResolver]; privacy decisions
 * are cross-checked against the immutable local privacy registry so a native/local policy desync is
 * reported as a transport error instead of silently trusted.
 *
 * Geo attribution is intentionally absent here: tv-core's GeoLookup is not filled yet, so the store
 * aggregates unknown countries into the honest "ZZ" bucket (no fake countries).
 */
class TvFlowTelemetryReader(
    context: Context,
    private val descriptor: ParcelFileDescriptor,
    private val store: TvTrafficStore,
    private val privacy: TvPrivacyIntelligence,
    private val settings: TvSettingsStore,
    private val onFatal: (String) -> Unit,
) : AutoCloseable {
    private val appContext = context.applicationContext
    private val owners = ConnectionOwnerResolver(appContext, capacity = 4096, ttlMillis = 5 * 60_000L)
    private val running = AtomicBoolean(true)
    private val expectedClose = AtomicBoolean(false)
    private val dedupe = EventDedupe(cap = 2048, windowMs = 60_000L)
    private val readerThread = Thread(::loop, "gedefense-tv-fullflow-telemetry").apply { isDaemon = true }
    private val labelCache = LinkedHashMap<String, String>(128, 0.75f, true)
    private val labelCacheLock = Any()
    private val firstEventLogged = AtomicBoolean(false)

    /** Bounded flow-id -> owner attribution so DNS events (which carry only the flow id) resolve. */
    private val flowOwners = object : LinkedHashMap<Long, String>(256, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, String>?): Boolean =
            size > MAX_TRACKED_FLOW_OWNERS
    }

    init {
        readerThread.start()
    }

    private fun loop() {
        var fatal: String? = null
        try {
            BufferedReader(
                InputStreamReader(FileInputStream(descriptor.fileDescriptor), Charsets.US_ASCII),
                16 * 1024,
            ).use { reader ->
                while (running.get()) {
                    val line = reader.readLine()
                    if (line == null) {
                        if (!expectedClose.get()) fatal = "fullflow_telemetry_eof"
                        break
                    }
                    if (line.length !in 2..MAX_FRAME_CHARS) {
                        fatal = "fullflow_telemetry_frame_invalid"
                        break
                    }
                    if (!handle(line)) {
                        fatal = "fullflow_telemetry_frame_invalid"
                        break
                    }
                }
            }
        } catch (_: Exception) {
            if (!expectedClose.get()) fatal = "fullflow_telemetry_io_failure"
        } finally {
            val reason = fatal
            if (reason != null && running.get()) onFatal(reason)
        }
    }

    private fun handle(line: String): Boolean {
        val parts = line.split('\t', limit = 12)
        return when (parts.firstOrNull()) {
            "O" -> handleOpen(parts)
            "U" -> handleUpdate(parts)
            "C" -> handleClose(parts)
            "B" -> handleBlocked(parts)
            "D" -> handleDns(parts)
            "P" -> handlePrivacy(parts)
            "Y" -> handleEncryptedDns(parts)
            "Q" -> handlePackageQuarantine(parts)
            "E" -> {
                store.transportError()
                true
            }
            else -> false
        }
    }

    private fun handleOpen(parts: List<String>): Boolean {
        if (parts.size != 10) return false
        val id = parts[1].toLongOrNull()?.takeIf { it >= 0L } ?: return false
        val protocol = parts[2].toIntOrNull() ?: return false
        val source = IpPrefix.parseAddress(parts[4]) ?: return false
        val sourcePort = parts[5].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val destination = IpPrefix.parseAddress(parts[6]) ?: return false
        val destinationPort = parts[7].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val action = TrafficAction.entries.getOrNull(parts[8].toIntOrNull() ?: -1) ?: return false
        parts[9].toULongOrNull() ?: return false
        val owner = owners.resolveTuple(protocol, source, sourcePort, destination, destinationPort)
            ?: UNRESOLVED_OWNER
        if (firstEventLogged.compareAndSet(false, true)) {
            Log.i("GeDefenseTvVpn", "telemetry first flow observed")
        }
        synchronized(flowOwners) { flowOwners[id] = owner }
        store.openFlow(
            flowId = id,
            owner = owner,
            label = labelFor(owner),
            destinationAddress = destination.toString(),
            destinationDomain = null,
            action = action,
            protocol = protocolName(protocol),
            openedAtMillis = System.currentTimeMillis(),
        )
        return true
    }

    private fun handleUpdate(parts: List<String>): Boolean {
        if (parts.size != 4) return false
        val id = parts[1].toLongOrNull() ?: return false
        val tx = parts[2].toLongOrNull() ?: return false
        val rx = parts[3].toLongOrNull() ?: return false
        store.updateFlow(id, tx, rx)
        return true
    }

    private fun handleClose(parts: List<String>): Boolean {
        if (parts.size != 5) return false
        val id = parts[1].toLongOrNull() ?: return false
        val tx = parts[2].toLongOrNull() ?: return false
        val rx = parts[3].toLongOrNull() ?: return false
        synchronized(flowOwners) { flowOwners.remove(id) }
        store.closeFlow(id, tx, rx)
        return true
    }

    private fun handleDns(parts: List<String>): Boolean {
        if (parts.size != 3) return false
        val id = parts[1].toLongOrNull() ?: return false
        val domain = parts[2]
        if (domain.length !in 1..253) return false
        val owner = synchronized(flowOwners) { flowOwners[id] } ?: UNRESOLVED_OWNER
        store.dnsQuery(owner, labelFor(owner), domain)
        return true
    }

    private fun handlePrivacy(parts: List<String>): Boolean {
        if (parts.size != 9) return false
        val nativeAction = parts[1].toIntOrNull()?.takeIf { it in 1..2 } ?: return false
        val protocol = parts[2].toIntOrNull() ?: return false
        val source = IpPrefix.parseAddress(parts[3]) ?: return false
        val sourcePort = parts[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val destination = IpPrefix.parseAddress(parts[5]) ?: return false
        val destinationPort = parts[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val domain = parts[7].takeIf { it.length in 1..253 } ?: return false
        val nativeRuleId = parts[8].takeIf { it.length in 3..96 } ?: return false
        val profile = settings.privacyProfile()
        val registry = try {
            privacy.registry(profile)
        } catch (_: Throwable) {
            null
        }
        val decision = registry?.decide(domain, profile.toCoreProfile())
        val expectedAction = when (decision?.action) {
            PrivacyAction.OBSERVE -> 1
            PrivacyAction.BLOCK -> 2
            else -> 0
        }
        if (decision == null || expectedAction != nativeAction || decision.ruleId != nativeRuleId) {
            store.transportError()
            return true
        }
        val owner = owners.resolveTuple(protocol, source, sourcePort, destination, destinationPort)
            ?: UNRESOLVED_OWNER
        val action = if (decision.action == PrivacyAction.BLOCK) TrafficAction.BLOCK else TrafficAction.ALLOW
        val key = "privacy:$owner:$domain:${decision.action.name}"
        if (dedupe.shouldEmit(key)) {
            store.privacyDecision(
                owner = owner,
                label = labelFor(owner),
                destinationAddress = destination.toString(),
                domain = domain,
                action = action,
                category = decision.category.name,
                ruleId = decision.ruleId,
            )
        }
        return true
    }

    private fun handleEncryptedDns(parts: List<String>): Boolean {
        if (parts.size != 8) return false
        val nativeAction = parts[1].toIntOrNull()?.takeIf { it in 1..2 } ?: return false
        val protocol = parts[2].toIntOrNull()?.takeIf { it == 6 || it == 17 } ?: return false
        val source = IpPrefix.parseAddress(parts[3]) ?: return false
        val sourcePort = parts[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val destination = IpPrefix.parseAddress(parts[5]) ?: return false
        val destinationPort = parts[6].toIntOrNull()?.takeIf { it == 853 } ?: return false
        val transport = parts[7].takeIf { it == "dot" || it == "doq" } ?: return false
        val profile = settings.privacyProfile()
        val expectedAction = when (profile) {
            TvPrivacyProfile.OFF -> 0
            TvPrivacyProfile.STRICT -> 2
            else -> 1
        }
        if (expectedAction != nativeAction) {
            store.transportError()
            return true
        }
        val owner = owners.resolveTuple(protocol, source, sourcePort, destination, destinationPort)
            ?: UNRESOLVED_OWNER
        val blocked = nativeAction == 2
        val key = "encrypted-dns:$owner:$transport:${profile.name}:$blocked"
        if (dedupe.shouldEmit(key)) {
            store.privacyDecision(
                owner = owner,
                label = labelFor(owner),
                destinationAddress = destination.toString(),
                domain = "encrypted-dns-$transport",
                action = if (blocked) TrafficAction.BLOCK else TrafficAction.ALLOW,
                category = "ENCRYPTED_DNS",
                ruleId = "transport-port-853",
            )
        }
        return true
    }

    private fun handlePackageQuarantine(parts: List<String>): Boolean {
        if (parts.size != 8) return false
        val protocol = parts[1].toIntOrNull() ?: return false
        val source = IpPrefix.parseAddress(parts[3]) ?: return false
        val sourcePort = parts[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val destination = IpPrefix.parseAddress(parts[5]) ?: return false
        val destinationPort = parts[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val bytes = parts[7].toLongOrNull()?.coerceIn(0L, MAX_BLOCKED_EVENT_BYTES) ?: return false
        val owner = owners.resolveTuple(protocol, source, sourcePort, destination, destinationPort)
            ?: UNRESOLVED_OWNER
        val key = "package-egress:$owner:$destination:$protocol:$destinationPort"
        if (dedupe.shouldEmit(key)) {
            store.recordBlocked(
                owner = owner,
                label = labelFor(owner),
                destinationAddress = destination.toString(),
                destinationDomain = null,
                bytes = bytes,
                protocol = protocolName(protocol),
                ruleHint = "package_quarantine",
            )
        }
        return true
    }

    private fun handleBlocked(parts: List<String>): Boolean {
        if (parts.size != 10) return false
        val protocol = parts[1].toIntOrNull() ?: return false
        val source = IpPrefix.parseAddress(parts[3]) ?: return false
        val sourcePort = parts[4].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val destination = IpPrefix.parseAddress(parts[5]) ?: return false
        val destinationPort = parts[6].toIntOrNull()?.takeIf { it in 1..65535 } ?: return false
        val action = parts[7].toIntOrNull() ?: return false
        parts[8].toULongOrNull() ?: return false
        val bytes = parts[9].toLongOrNull()?.coerceIn(0L, MAX_BLOCKED_EVENT_BYTES) ?: return false
        if (action != BLOCK_ACTION) return false
        val owner = owners.resolveTuple(protocol, source, sourcePort, destination, destinationPort)
            ?: UNRESOLVED_OWNER
        val key = "$destination|$protocol|$owner"
        if (dedupe.shouldEmit(key)) {
            store.recordBlocked(
                owner = owner,
                label = labelFor(owner),
                destinationAddress = destination.toString(),
                destinationDomain = null,
                bytes = bytes,
                protocol = protocolName(protocol),
                ruleHint = "threat_policy",
            )
        }
        return true
    }

    private fun labelFor(owner: String): String {
        if (owner.startsWith("uid:") || owner == UNRESOLVED_OWNER) return owner.take(120)
        val packageName = owner.substringBefore(',')
        synchronized(labelCacheLock) { labelCache[packageName]?.let { return it } }
        val label = try {
            val applicationInfo = appContext.packageManager.getApplicationInfo(packageName, 0)
            appContext.packageManager.getApplicationLabel(applicationInfo).toString().take(120)
        } catch (_: Exception) {
            packageName.take(120)
        }
        synchronized(labelCacheLock) {
            labelCache[packageName] = label
            while (labelCache.size > LABEL_CACHE_CAPACITY) {
                val iterator = labelCache.entries.iterator()
                if (!iterator.hasNext()) break
                iterator.next()
                iterator.remove()
            }
        }
        return label
    }

    private fun protocolName(protocol: Int): String = when (protocol) {
        6 -> "tcp"
        17 -> "udp"
        else -> "ip"
    }

    private fun TvPrivacyProfile.toCoreProfile(): PrivacyProfile = when (this) {
        TvPrivacyProfile.OFF -> PrivacyProfile.OFF
        TvPrivacyProfile.CONSERVATIVE -> PrivacyProfile.CONSERVATIVE
        TvPrivacyProfile.BALANCED -> PrivacyProfile.BALANCED
        TvPrivacyProfile.STRICT -> PrivacyProfile.STRICT
    }

    override fun close() {
        expectedClose.set(true)
        running.set(false)
        try {
            descriptor.close()
        } catch (error: Exception) {
            RuntimeFailureLog.nonCritical("full-flow-analytics", error)
        }
        readerThread.interrupt()
        owners.clear()
    }

    companion object {
        private const val MAX_FRAME_CHARS = 1024
        private const val MAX_BLOCKED_EVENT_BYTES = 65_535L
        private const val BLOCK_ACTION = 3
        private const val UNRESOLVED_OWNER = "uid-unresolved"
        private const val LABEL_CACHE_CAPACITY = 512
        private const val MAX_TRACKED_FLOW_OWNERS = 2_000
    }
}

/** Small bounded de-duplicator so repeated native events cannot spam the store/XDR sink. */
internal class EventDedupe(private val cap: Int = 4096, private val windowMs: Long = 60_000L) {
    private val seen = object : LinkedHashMap<String, Long>(cap, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, Long>?): Boolean = size > cap
    }

    @Synchronized
    fun shouldEmit(key: String, now: Long = System.currentTimeMillis()): Boolean {
        val last = seen[key]
        if (last != null && now - last < windowMs) return false
        seen[key] = now
        return true
    }
}
