package de.visiongaia.gedefense.tv.vpn

import android.content.Context
import android.net.ConnectivityManager
import android.os.Build
import android.os.ParcelFileDescriptor
import de.visiongaia.gedefense.mobile.core.IpAddress
import de.visiongaia.gedefense.mobile.core.PacketParser
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

/**
 * Session-scoped Android authority for package-specific Full-Flow egress quarantine.
 *
 * Ported from the mobile dossier. GaiaNet owns forwarding but Android owns UID attribution: while the
 * quarantine snapshot is non-empty, the helper asks this responder about each new TCP/UDP flow before
 * opening a direct upstream socket. The request/response protocol is fixed-size. Resolver timeout,
 * malformed framing and unknown ownership deny the queried flow while quarantine is active.
 *
 * The TV V2 release starts with an empty quarantine set (no per-app block list in this scope); the
 * responder is still installed so the helper descriptor contract is unchanged and a future per-app
 * policy can be added without a native protocol change. `getConnectionOwnerUid` requires API 29; below
 * that the responder denies any (currently unused) quarantine query instead of guessing ownership.
 */
class PackageEgressGateResponder(
    context: Context,
    private val descriptor: ParcelFileDescriptor,
    initialQuarantine: Set<String>,
) : AutoCloseable {
    private val appContext = context.applicationContext
    private val connectivity = appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
    private val packages = AtomicReference(sanitizePackages(initialQuarantine))
    private val running = AtomicBoolean(true)
    private val closed = AtomicBoolean(false)
    private val worker = Thread(::loop, "gedefense-tv-package-egress-gate").apply { isDaemon = true }

    init {
        worker.start()
    }

    fun updateQuarantine(next: Set<String>) {
        packages.set(sanitizePackages(next))
    }

    fun enabled(): Boolean = packages.get().isNotEmpty()

    private fun loop() {
        val input = FileInputStream(descriptor.fileDescriptor)
        val output = FileOutputStream(descriptor.fileDescriptor)
        val request = ByteArray(REQUEST_BYTES)
        val response = ByteArray(RESPONSE_BYTES)
        try {
            while (running.get()) {
                if (!readFully(input, request)) break
                val parsed = parse(request)
                val verdict = if (parsed == null) VERDICT_DENY else resolveVerdict(parsed)
                RESPONSE_MAGIC.copyInto(response, 0)
                val requestId = parsed?.requestId ?: requestIdOrZero(request)
                response[4] = (requestId ushr 24).toByte()
                response[5] = (requestId ushr 16).toByte()
                response[6] = (requestId ushr 8).toByte()
                response[7] = requestId.toByte()
                response[8] = verdict
                response[9] = 0
                response[10] = 0
                response[11] = 0
                try {
                    output.write(response)
                    output.flush()
                } catch (_: IOException) {
                    break
                }
            }
        } catch (_: IOException) {
            // Session teardown closes the descriptor to wake this blocking reader.
        } finally {
            running.set(false)
        }
    }

    private fun resolveVerdict(request: Request): Byte {
        val quarantine = packages.get()
        if (quarantine.isEmpty()) return VERDICT_ALLOW
        if (Build.VERSION.SDK_INT < 29) return VERDICT_DENY
        val manager = connectivity ?: return VERDICT_DENY
        val ownerPackages = try {
            BoundedAndroidCall.call(OWNER_RESOLVE_TIMEOUT_MS) {
                val uid = manager.getConnectionOwnerUid(
                    request.protocol,
                    InetSocketAddress(request.source.toInetAddress(), request.sourcePort),
                    InetSocketAddress(request.destination.toInetAddress(), request.destinationPort),
                )
                if (uid < 0) return@call emptyList<String>()
                appContext.packageManager.getPackagesForUid(uid)
                    ?.asSequence()
                    ?.filter(::validPackageName)
                    ?.distinct()
                    ?.take(MAX_PACKAGES_PER_UID)
                    ?.toList()
                    .orEmpty()
            }
        } catch (_: RuntimeException) {
            emptyList()
        }
        if (ownerPackages.isEmpty()) return VERDICT_DENY
        return if (ownerPackages.any { it in quarantine }) VERDICT_DENY else VERDICT_ALLOW
    }

    private fun parse(bytes: ByteArray): Request? {
        if (bytes.size != REQUEST_BYTES || bytes[0] != REQUEST_MAGIC[0] || bytes[1] != REQUEST_MAGIC[1] ||
            bytes[2] != REQUEST_MAGIC[2] || bytes[3] != REQUEST_MAGIC[3]
        ) {
            return null
        }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
        buffer.position(4)
        val requestId = buffer.int
        if (requestId == 0) return null
        val protocol = buffer.get().toInt() and 0xff
        val version = buffer.get().toInt() and 0xff
        if (buffer.get().toInt() != 0 || buffer.get().toInt() != 0) return null
        if (protocol != PacketParser.TCP && protocol != PacketParser.UDP) return null
        if (version != 4 && version != 6) return null
        val src = ByteArray(16).also(buffer::get)
        val dst = ByteArray(16).also(buffer::get)
        val sourcePort = buffer.short.toInt() and 0xffff
        val destinationPort = buffer.short.toInt() and 0xffff
        if (sourcePort !in 1..65535 || destinationPort !in 1..65535) return null
        val source = decodeAddress(version, src) ?: return null
        val destination = decodeAddress(version, dst) ?: return null
        return Request(requestId, protocol, source, sourcePort, destination, destinationPort)
    }

    private fun decodeAddress(version: Int, bytes: ByteArray): IpAddress? {
        if (bytes.size != 16) return null
        return if (version == 4) {
            // Go netip.Addr.As16() represents IPv4 as ::ffff:a.b.c.d.
            if ((0 until 10).any { bytes[it] != 0.toByte() } || bytes[10] != 0xff.toByte() || bytes[11] != 0xff.toByte()) {
                return null
            }
            val value = ((bytes[12].toInt() and 0xff) shl 24) or
                ((bytes[13].toInt() and 0xff) shl 16) or
                ((bytes[14].toInt() and 0xff) shl 8) or
                (bytes[15].toInt() and 0xff)
            IpAddress(4, v4 = value)
        } else {
            IpAddress(6, v6Hi = readLong(bytes, 0), v6Lo = readLong(bytes, 8))
        }
    }

    private fun requestIdOrZero(bytes: ByteArray): Int = if (bytes.size >= 8) {
        ByteBuffer.wrap(bytes, 4, 4).order(ByteOrder.BIG_ENDIAN).int
    } else {
        0
    }

    private fun readFully(input: FileInputStream, out: ByteArray): Boolean {
        var offset = 0
        while (offset < out.size && running.get()) {
            val read = input.read(out, offset, out.size - offset)
            if (read < 0) return false
            if (read == 0) continue
            offset += read
        }
        return offset == out.size
    }

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        running.set(false)
        try {
            descriptor.close()
        } catch (error: IOException) {
            RuntimeFailureLog.nonCritical("package-egress-gate", error)
        }
        if (Thread.currentThread() !== worker) {
            try {
                worker.join(250L)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
            }
        }
    }

    private data class Request(
        val requestId: Int,
        val protocol: Int,
        val source: IpAddress,
        val sourcePort: Int,
        val destination: IpAddress,
        val destinationPort: Int,
    )

    companion object {
        private const val REQUEST_BYTES = 48
        private const val RESPONSE_BYTES = 12
        private const val OWNER_RESOLVE_TIMEOUT_MS = 250L
        private const val MAX_PACKAGES = 256
        private const val MAX_PACKAGES_PER_UID = 8
        private const val VERDICT_ALLOW: Byte = 1
        private const val VERDICT_DENY: Byte = 2
        private val REQUEST_MAGIC = byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'Q'.code.toByte(), '1'.code.toByte())
        private val RESPONSE_MAGIC = byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'A'.code.toByte(), 'Q'.code.toByte())
        private val PACKAGE_PATTERN = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")

        private fun sanitizePackages(input: Set<String>): Set<String> = input.asSequence()
            .map(String::trim)
            .filter(::validPackageName)
            .distinct()
            .take(MAX_PACKAGES)
            .toCollection(LinkedHashSet())

        private fun validPackageName(value: String): Boolean = value.length in 3..256 && PACKAGE_PATTERN.matches(value)

        private fun readLong(bytes: ByteArray, offset: Int): Long {
            var value = 0L
            for (i in 0 until 8) value = (value shl 8) or (bytes[offset + i].toLong() and 0xffL)
            return value
        }
    }
}
