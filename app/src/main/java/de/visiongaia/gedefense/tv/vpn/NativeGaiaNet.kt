package de.visiongaia.gedefense.tv.vpn

import android.content.Context
import android.os.Build
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.ParcelFileDescriptor
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import de.visiongaia.gedefense.mobile.core.EnforcementClass
import de.visiongaia.gedefense.mobile.core.PrivacyAction
import de.visiongaia.gedefense.mobile.core.PrivacyIntelligenceRegistry
import de.visiongaia.gedefense.mobile.core.PrivacyProfile
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.io.File
import java.io.FileDescriptor
import java.io.FileOutputStream
import java.io.IOException
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-isolated bridge for the vendored GaiaNet v2 data plane — TV port.
 *
 * Differences from the mobile original: DIRECT egress only (no WireGuard profile/config pipe and no
 * VPN-socket protector descriptor). Android hands the helper exactly five descriptors: TUN, telemetry
 * writer, authenticated threat policy, immutable privacy policy and the package-egress gate socket.
 * No shell is involved and the control protocol is fixed-size.
 */
object NativeGaiaNet {
    private const val HELPER_NAME = "libgedefense_gaianet_v2.so"
    private const val MAX_THREAT_RECORDS = 150_000
    private const val PROTOCOL_VERSION: Byte = 5
    private const val TOKEN_BYTES = 32
    private const val HELPER_INIT_BYTES = 44
    private const val TUN_MTU = 1280
    private const val CONNECT_TIMEOUT_MS = 4_000
    private const val HANDSHAKE_TIMEOUT_MS = 7_000
    private const val CONNECT_RETRY_MS = 20L
    private const val HELPER_MIN_BYTES = 128 * 1024L
    private const val HELPER_MAX_BYTES = 16 * 1024 * 1024L
    private const val HELPER_FRAME_BYTES = 8
    private const val SOCKET_PROTECT_REJECTED = 1
    private val secureRandom = SecureRandom()

    @Volatile
    private var helperExecutable: File? = null

    @Volatile
    private var activeSession: Session? = null

    @Volatile
    private var lastStartFailureCode: String? = null

    val lastStartFailure: String?
        get() = lastStartFailureCode

    fun initialize(context: Context) {
        val candidate = File(context.applicationInfo.nativeLibraryDir, HELPER_NAME)
        val expectedSha = when (Build.SUPPORTED_ABIS.firstOrNull()) {
            "arm64-v8a" -> de.visiongaia.gedefense.tv.BuildConfig.GAIANET_SHA_ARM64
            "x86_64" -> de.visiongaia.gedefense.tv.BuildConfig.GAIANET_SHA_X86_64
            else -> null
        }
        val digestOk = expectedSha == null || sha256OfFile(candidate) == expectedSha
        if (!digestOk) {
            lastStartFailureCode = "helper_integrity_mismatch"
            android.util.Log.e("GeDefenseTvVpn", "GaiaNet helper integrity mismatch; refusing to execute")
        }
        helperExecutable = candidate.takeIf {
            digestOk && it.isFile && it.length() in HELPER_MIN_BYTES..HELPER_MAX_BYTES && it.canExecute() && hasElfMagic(it)
        }
    }

    private fun sha256OfFile(file: File): String? {
        return try {
            if (!file.isFile) {
                null
            } else {
                val digest = java.security.MessageDigest.getInstance("SHA-256")
                file.inputStream().use { stream ->
                    val buffer = ByteArray(64 * 1024)
                    while (true) {
                        val read = stream.read(buffer)
                        if (read <= 0) break
                        digest.update(buffer, 0, read)
                    }
                }
                digest.digest().joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }
            }
        } catch (_: Throwable) {
            null
        }
    }

    val available: Boolean
        get() = helperExecutable?.let { it.isFile && it.canExecute() && hasElfMagic(it) } == true

    data class Session internal constructor(
        val telemetryRead: ParcelFileDescriptor,
        private val control: LocalSocket,
        private val process: Process,
        private val socketFile: File,
        private val tunnelAnchor: ParcelFileDescriptor,
        private val packageEgressGate: PackageEgressGateResponder,
    ) : AutoCloseable {
        private val closed = AtomicBoolean(false)
        private val writeLock = Any()

        fun setPowerConstrained(constrained: Boolean): Boolean = sendControl('P', constrained)

        fun setTelemetryDetailed(detailed: Boolean): Boolean = sendControl('V', detailed)

        fun isProcessAlive(): Boolean = !closed.get() && process.isAlive

        private fun sendControl(kind: Char, enabled: Boolean): Boolean {
            if (closed.get()) return false
            return synchronized(writeLock) {
                if (closed.get()) return@synchronized false
                try {
                    control.outputStream.write(byteArrayOf(kind.code.toByte(), if (enabled) 1 else 0))
                    control.outputStream.flush()
                    true
                } catch (_: IOException) {
                    false
                }
            }
        }

        override fun close() {
            if (!closed.compareAndSet(false, true)) return
            synchronized(writeLock) {
                try {
                    control.outputStream.write(byteArrayOf('S'.code.toByte(), 0))
                    control.outputStream.flush()
                } catch (error: IOException) {
                    RuntimeFailureLog.nonCritical("native-gaia-net", error)
                }
            }
            try {
                control.close()
            } catch (error: IOException) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
            try {
                telemetryRead.close()
            } catch (error: IOException) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
            try {
                if (!process.waitFor(350, TimeUnit.MILLISECONDS)) {
                    process.destroy()
                    if (!process.waitFor(250, TimeUnit.MILLISECONDS)) process.destroyForcibly()
                }
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                process.destroyForcibly()
            } catch (_: RuntimeException) {
                process.destroyForcibly()
            } finally {
                packageEgressGate.close()
                // Keep the Android VPN interface alive until the helper has fully stopped. If the helper
                // crashes, this descriptor remains open in the service process and therefore preserves
                // fail-closed routing until recovery replaces the tunnel or the operator stops protection.
                tunnelAnchor.closeSafely()
            }
            socketFile.delete()
            clearSession(this)
        }
    }

    @Synchronized
    fun start(
        context: Context,
        tunnel: ParcelFileDescriptor,
        index: ThreatIndex,
        privacyRegistry: PrivacyIntelligenceRegistry,
        privacyProfile: PrivacyProfile,
        cacheDir: File,
        powerConstrained: Boolean,
        telemetryDetailed: Boolean,
    ): Session? {
        lastStartFailureCode = null
        // SECV2-14: hard cap on policy/index size; fail honestly instead of exhausting memory.
        if (index.count > MAX_THREAT_RECORDS) {
            lastStartFailureCode = "policy_too_large"
            return null
        }
        if (activeSession != null) {
            lastStartFailureCode = "session_already_active"
            return null
        }
        val helper = helperExecutable?.takeIf { available } ?: run {
            lastStartFailureCode = "helper_unavailable"
            return null
        }
        val policy = ThreatPolicyBinary.create(index, cacheDir) ?: run {
            lastStartFailureCode = "policy_serialize_failed"
            return null
        }
        val privacyPolicy = PrivacyPolicyBinary.create(privacyRegistry, privacyProfile, cacheDir) ?: run {
            lastStartFailureCode = "privacy_policy_serialize_failed"
            policy.closeSafely()
            return null
        }
        val pipe = try {
            ParcelFileDescriptor.createPipe()
        } catch (_: IOException) {
            lastStartFailureCode = "telemetry_pipe_failed"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            return null
        }
        val packageGatePair = try {
            ParcelFileDescriptor.createSocketPair()
        } catch (_: IOException) {
            lastStartFailureCode = "package_egress_gate_socket_failed"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            return null
        }
        val packageGateResponder = try {
            PackageEgressGateResponder(context, packageGatePair[0], emptySet())
        } catch (_: RuntimeException) {
            lastStartFailureCode = "package_egress_gate_responder_failed"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            closePipe(packageGatePair)
            return null
        }
        val token = ByteArray(TOKEN_BYTES).also(secureRandom::nextBytes)
        val tokenHex = token.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        val socketFile = File(cacheDir, "gdtv2-${tokenHex.take(16)}.sock")
        if (socketFile.absolutePath.length > 96) {
            lastStartFailureCode = "control_path_invalid"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            packageGateResponder.close()
            packageGatePair[1].closeSafely()
            return null
        }
        socketFile.delete()

        val process = try {
            ProcessBuilder(helper.absolutePath, "--control", socketFile.absolutePath, "--token", tokenHex)
                .redirectErrorStream(true)
                .start()
        } catch (_: IOException) {
            lastStartFailureCode = "helper_exec_failed"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            packageGateResponder.close()
            packageGatePair[1].closeSafely()
            return null
        } catch (_: SecurityException) {
            lastStartFailureCode = "helper_exec_denied"
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            packageGateResponder.close()
            packageGatePair[1].closeSafely()
            return null
        }
        drainProcessOutput(process)

        val control = connectControl(socketFile, process) ?: run {
            lastStartFailureCode = "helper_connect_failed"
            process.destroyForcibly()
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            packageGateResponder.close()
            packageGatePair[1].closeSafely()
            socketFile.delete()
            return null
        }
        return try {
            control.soTimeout = HANDSHAKE_TIMEOUT_MS
            control.setFileDescriptorsForSend(
                arrayOf(
                    tunnel.fileDescriptor,
                    pipe[1].fileDescriptor,
                    policy.fileDescriptor,
                    privacyPolicy.fileDescriptor,
                    packageGatePair[1].fileDescriptor,
                ),
            )
            val frame = ByteArray(HELPER_INIT_BYTES)
            frame[0] = 'G'.code.toByte()
            frame[1] = 'D'.code.toByte()
            frame[2] = 'V'.code.toByte()
            frame[3] = '2'.code.toByte()
            frame[4] = PROTOCOL_VERSION
            frame[5] = if (powerConstrained) 1 else 0
            frame[6] = if (telemetryDetailed) 1 else 0
            frame[7] = 0 // DIRECT egress only.
            token.copyInto(frame, destinationOffset = 8)
            frame[40] = (TUN_MTU ushr 8).toByte()
            frame[41] = TUN_MTU.toByte()
            frame[42] = if (packageGateResponder.enabled()) 1 else 0
            control.outputStream.write(frame)
            control.outputStream.flush()

            awaitStartupReady(control)

            // SCM_RIGHTS duplicated the helper descriptors. Keep the original TUN descriptor as a
            // service-process liveness anchor: a helper crash must not tear down the Android VPN
            // interface and expose a direct-routing window before recovery runs.
            pipe[1].closeSafely()
            policy.closeSafely()
            privacyPolicy.closeSafely()
            packageGatePair[1].closeSafely()
            control.soTimeout = 0
            Session(pipe[0], control, process, socketFile, tunnel, packageGateResponder).also {
                lastStartFailureCode = null
                activeSession = it
            }
        } catch (_: Exception) {
            if (lastStartFailureCode == null) lastStartFailureCode = "helper_handshake_failed"
            try {
                control.close()
            } catch (error: IOException) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
            process.destroyForcibly()
            policy.closeSafely()
            privacyPolicy.closeSafely()
            closePipe(pipe)
            packageGateResponder.close()
            packageGatePair[1].closeSafely()
            socketFile.delete()
            null
        }
    }

    private data class HelperFrame(
        val bytes: ByteArray,
        val descriptors: Array<FileDescriptor>?,
    )

    private fun awaitStartupReady(control: LocalSocket) {
        while (true) {
            val received = receiveHelperFrame(control)
            val frame = received.bytes
            when {
                hasMagic(frame, 'G', 'D', 'P', '2') -> {
                    // DIRECT mode never requests socket protection from the app.
                    closeAncillaryDescriptors(received.descriptors)
                    lastStartFailureCode = "unexpected_socket_protection_request"
                    sendSocketProtectionAck(control, SOCKET_PROTECT_REJECTED)
                    throw IOException("Unexpected socket protection request")
                }
                hasMagic(frame, 'G', 'D', 'A', '2') -> {
                    if (!received.descriptors.isNullOrEmpty()) {
                        closeAncillaryDescriptors(received.descriptors)
                        lastStartFailureCode = "helper_ack_has_descriptors"
                        throw IOException("GaiaNet helper acknowledgement carried unexpected descriptors")
                    }
                    val status = decodeStatus(frame)
                    if (status != 0) {
                        lastStartFailureCode = when (status) {
                            74 -> "policy_rejected"
                            75 -> "engine_init_failed"
                            79 -> "privacy_policy_rejected"
                            80 -> "package_egress_gate_rejected"
                            else -> "helper_status_$status"
                        }
                        throw IOException("GaiaNet helper rejected startup")
                    }
                    return
                }
                else -> {
                    closeAncillaryDescriptors(received.descriptors)
                    lastStartFailureCode = "helper_ack_invalid"
                    throw IOException("GaiaNet helper acknowledgement invalid")
                }
            }
        }
    }

    private fun receiveHelperFrame(control: LocalSocket): HelperFrame {
        val frame = ByteArray(HELPER_FRAME_BYTES)
        var offset = 0
        var descriptors: Array<FileDescriptor>? = null
        while (offset < frame.size) {
            val read = control.inputStream.read(frame, offset, frame.size - offset)
            if (read < 0) {
                closeAncillaryDescriptors(descriptors)
                throw IOException("GaiaNet helper control channel closed")
            }
            if (read == 0) continue
            val justReceived = try {
                control.ancillaryFileDescriptors
            } catch (_: IOException) {
                null
            }
            if (!justReceived.isNullOrEmpty()) {
                if (descriptors != null) {
                    closeAncillaryDescriptors(justReceived)
                    closeAncillaryDescriptors(descriptors)
                    throw IOException("Multiple ancillary descriptor batches in helper frame")
                }
                descriptors = justReceived
            }
            offset += read
        }
        return HelperFrame(frame, descriptors)
    }

    private fun sendSocketProtectionAck(control: LocalSocket, status: Int) {
        val frame = byteArrayOf(
            'G'.code.toByte(), 'D'.code.toByte(), 'R'.code.toByte(), '2'.code.toByte(),
            (status ushr 24).toByte(), (status ushr 16).toByte(), (status ushr 8).toByte(), status.toByte(),
        )
        control.outputStream.write(frame)
        control.outputStream.flush()
    }

    private fun closeAncillaryDescriptors(descriptors: Array<FileDescriptor>?) {
        descriptors?.forEach { descriptor ->
            try {
                Os.close(descriptor)
            } catch (error: ErrnoException) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
        }
    }

    private fun hasMagic(frame: ByteArray, a: Char, b: Char, c: Char, d: Char): Boolean =
        frame.size == HELPER_FRAME_BYTES && frame[0] == a.code.toByte() && frame[1] == b.code.toByte() &&
            frame[2] == c.code.toByte() && frame[3] == d.code.toByte()

    private fun decodeStatus(frame: ByteArray): Int =
        ((frame[4].toInt() and 0xff) shl 24) or ((frame[5].toInt() and 0xff) shl 16) or
            ((frame[6].toInt() and 0xff) shl 8) or (frame[7].toInt() and 0xff)

    fun setPowerConstrained(constrained: Boolean): Boolean = activeSession?.setPowerConstrained(constrained) ?: false

    fun setTelemetryDetailed(detailed: Boolean): Boolean = activeSession?.setTelemetryDetailed(detailed) ?: false

    fun stop() {
        activeSession?.close()
    }

    @Synchronized
    private fun clearSession(session: Session) {
        if (activeSession === session) activeSession = null
    }

    private fun connectControl(socketFile: File, process: Process): LocalSocket? {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(CONNECT_TIMEOUT_MS.toLong())
        while (System.nanoTime() < deadline && process.isAlive) {
            val socket = LocalSocket()
            try {
                // Android LocalSocket does not implement a connect(endpoint, timeout) overload; the
                // outer monotonic deadline remains the startup bound and a missing AF_UNIX socket fails
                // immediately and is retried.
                socket.connect(LocalSocketAddress(socketFile.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                return socket
            } catch (_: IOException) {
                try {
                    socket.close()
                } catch (error: IOException) {
                    RuntimeFailureLog.nonCritical("native-gaia-net", error)
                }
                try {
                    Thread.sleep(CONNECT_RETRY_MS)
                } catch (_: InterruptedException) {
                    Thread.currentThread().interrupt()
                    return null
                }
            }
        }
        return null
    }

    private fun drainProcessOutput(process: Process) {
        Thread({
            try {
                process.inputStream.use { input ->
                    val buffer = ByteArray(1024)
                    while (input.read(buffer) >= 0) {
                        /* bounded discard: helper emits no routine logs */
                    }
                }
            } catch (error: IOException) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
        }, "gedefense-tv-gaianet-logdrain").apply { isDaemon = true; start() }
    }

    private fun hasElfMagic(file: File): Boolean = try {
        file.inputStream().use { input ->
            val magic = ByteArray(4)
            input.read(magic) == 4 && magic[0] == 0x7f.toByte() &&
                magic[1] == 'E'.code.toByte() && magic[2] == 'L'.code.toByte() && magic[3] == 'F'.code.toByte()
        }
    } catch (_: IOException) {
        false
    }

    private fun closePipe(pipe: Array<ParcelFileDescriptor>) = pipe.forEach { it.closeSafely() }
    private fun ParcelFileDescriptor.closeSafely() {
        try {
            close()
        } catch (error: IOException) {
            RuntimeFailureLog.nonCritical("native-gaia-net", error)
        }
    }
}

private object ThreatPolicyBinary {
    fun create(index: ThreatIndex, cacheDir: File): ParcelFileDescriptor? {
        if (!cacheDir.isDirectory && !cacheDir.mkdirs()) return null
        val file = try {
            File.createTempFile("gdtv-policy-", ".bin", cacheDir)
        } catch (_: IOException) {
            return null
        }
        return try {
            try {
                Os.chmod(file.absolutePath, OsConstants.S_IRUSR or OsConstants.S_IWUSR)
            } catch (error: Exception) {
                RuntimeFailureLog.nonCritical("native-gaia-net", error)
            }
            FileOutputStream(file).use { raw ->
                DataOutputStream(raw).use { out ->
                    out.write(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'T'.code.toByte(), 'I'.code.toByte()))
                    out.writeByte(2)
                    out.write(byteArrayOf(0, 0, 0))
                    out.writeInt(index.count)
                    out.write(hexToBytes(index.fullPolicySha256))
                    var written = 0
                    index.forEachPolicyRecord { prefix, bits, enforcement ->
                        out.writeByte(prefix.family)
                        out.writeByte(prefix.prefixLength)
                        out.writeByte(actionCode(enforcement))
                        out.writeByte(0)
                        out.writeLong(bits)
                        if (prefix.family == 4) {
                            out.writeInt(prefix.v4)
                        } else {
                            out.writeLong(prefix.v6Hi)
                            out.writeLong(prefix.v6Lo)
                        }
                        written++
                    }
                    if (written != index.count) throw IOException("threat policy record count mismatch")
                    out.flush()
                    raw.fd.sync()
                }
            }
            val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
            file.delete()
            pfd
        } catch (_: Exception) {
            file.delete()
            null
        }
    }

    private fun actionCode(enforcement: EnforcementClass): Int = when (enforcement) {
        EnforcementClass.ANNOTATE_ONLY -> 1
        EnforcementClass.CORRELATE_ONLY -> 2
        EnforcementClass.ROUTE_BLOCK -> 3
    }

    private fun hexToBytes(value: String): ByteArray {
        if (!value.matches(Regex("[0-9a-f]{64}"))) throw IOException("threat policy fingerprint invalid")
        return ByteArray(32) { index -> value.substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }
}

private object PrivacyPolicyBinary {
    private const val VERSION = 1
    private const val MAX_RULES = 8_192
    private const val MAX_ID_BYTES = 96
    private const val MAX_DOMAIN_BYTES = 253

    fun create(registry: PrivacyIntelligenceRegistry, profile: PrivacyProfile, cacheDir: File): ParcelFileDescriptor? {
        if (!cacheDir.isDirectory && !cacheDir.mkdirs()) return null
        val records = try {
            registry.policyRecords(profile)
        } catch (_: RuntimeException) {
            return null
        }
        if (records.size > MAX_RULES) return null
        val body = ByteArrayOutputStream((records.size * 80).coerceAtMost(4 * 1024 * 1024))
        return try {
            DataOutputStream(body).use { out ->
                for (record in records) {
                    val id = record.id.toByteArray(Charsets.US_ASCII)
                    val domain = record.domain.toByteArray(Charsets.US_ASCII)
                    if (id.size !in 3..MAX_ID_BYTES || domain.size !in 1..MAX_DOMAIN_BYTES) {
                        throw IOException("privacy policy record bound invalid")
                    }
                    var flags = 0
                    if (record.includeSubdomains) flags = flags or 0x01
                    if (record.essential) flags = flags or 0x02
                    out.writeByte(flags)
                    out.writeByte(record.confidence.ordinal)
                    out.writeByte(record.breakageRisk.ordinal)
                    out.writeByte(actionCode(record.action))
                    out.writeShort(id.size)
                    out.writeShort(domain.size)
                    out.write(id)
                    out.write(domain)
                }
            }
            val payload = body.toByteArray()
            val digest = MessageDigest.getInstance("SHA-256").digest(payload)
            val file = File.createTempFile("gdtv-privacy-", ".bin", cacheDir)
            try {
                try {
                    Os.chmod(file.absolutePath, OsConstants.S_IRUSR or OsConstants.S_IWUSR)
                } catch (error: Exception) {
                    RuntimeFailureLog.nonCritical("native-gaia-net", error)
                }
                FileOutputStream(file).use { raw ->
                    DataOutputStream(raw).use { out ->
                        out.write(byteArrayOf('G'.code.toByte(), 'D'.code.toByte(), 'P'.code.toByte(), 'I'.code.toByte()))
                        out.writeByte(VERSION)
                        out.writeByte(profile.ordinal)
                        out.write(byteArrayOf(0, 0))
                        out.writeInt(records.size)
                        out.write(digest)
                        out.write(payload)
                        out.flush()
                        raw.fd.sync()
                    }
                }
                val pfd = ParcelFileDescriptor.open(file, ParcelFileDescriptor.MODE_READ_ONLY)
                file.delete()
                pfd
            } catch (error: Exception) {
                file.delete()
                throw error
            } finally {
                payload.fill(0)
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun actionCode(action: PrivacyAction): Int = when (action) {
        PrivacyAction.ALLOW -> 0
        PrivacyAction.OBSERVE -> 1
        PrivacyAction.BLOCK -> 2
    }
}
