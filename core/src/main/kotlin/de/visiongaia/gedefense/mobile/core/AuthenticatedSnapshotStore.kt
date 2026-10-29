package de.visiongaia.gedefense.mobile.core

import java.io.BufferedInputStream
import java.io.BufferedOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.File
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardOpenOption
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.ProviderException
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKey

enum class AuthenticatedSnapshotState { ABSENT, VALID, INVALID }

/**
 * Machine-readable failure class for an INVALID authenticated snapshot read.
 *
 * Integrity failures are deliberately distinct from Android/OEM key-provider availability failures.
 * Callers may use that distinction to implement narrowly-scoped recovery for reconstructible state,
 * but must never treat either class as a valid/empty snapshot.
 */
enum class AuthenticatedSnapshotFailureKind {
    NONE,
    KEY_UNAVAILABLE,
    KEY_OPERATION,
    IO_UNAVAILABLE,
    FORMAT_INVALID,
    AUTHENTICATION_FAILED,
    RUNTIME_FAILURE,
}

data class AuthenticatedSnapshotRead(
    val state: AuthenticatedSnapshotState,
    val payload: ByteArray? = null,
    val reason: String? = null,
    val failureKind: AuthenticatedSnapshotFailureKind = AuthenticatedSnapshotFailureKind.NONE,
)

/**
 * Bounded, authenticated, crash-resistant snapshot persistence.
 *
 * The envelope is intentionally binary and fixed-width around the payload so parsing cannot be
 * influenced by attacker-controlled JSON metadata. Authentication covers the magic, schema,
 * payload length and payload bytes. A failed authentication is never interpreted as an empty state.
 */
class AuthenticatedSnapshotStore(
    private val file: File,
    private val key: SecretKey?,
    private val schemaVersion: Int,
    private val maxPayloadBytes: Int,
    private val keyProvider: (() -> SecretKey?)? = null,
) {
    private val lock = Any()
    private val random = SecureRandom()

    init {
        require(schemaVersion in 1..Int.MAX_VALUE)
        require(maxPayloadBytes in 1..MAX_PAYLOAD_LIMIT)
    }

    fun read(): AuthenticatedSnapshotRead = synchronized(lock) {
        val activeKey = try {
            resolveKey()
        } catch (_: GeneralSecurityException) {
            return@synchronized invalid(
                "snapshot key operation failed",
                AuthenticatedSnapshotFailureKind.KEY_OPERATION,
            )
        } catch (_: ProviderException) {
            return@synchronized invalid(
                "snapshot key operation failed",
                AuthenticatedSnapshotFailureKind.KEY_OPERATION,
            )
        } catch (_: RuntimeException) {
            return@synchronized invalid(
                "snapshot key operation failed",
                AuthenticatedSnapshotFailureKind.KEY_OPERATION,
            )
        }
        if (activeKey == null) {
            return@synchronized invalid(
                "snapshot key unavailable",
                AuthenticatedSnapshotFailureKind.KEY_UNAVAILABLE,
            )
        }
        val path = file.toPath()
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            return@synchronized AuthenticatedSnapshotRead(AuthenticatedSnapshotState.ABSENT)
        }
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            return@synchronized invalid("snapshot is not a regular file", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
        }
        val length = try {
            Files.size(path)
        } catch (_: IOException) {
            return@synchronized invalid("snapshot stat failed", AuthenticatedSnapshotFailureKind.IO_UNAVAILABLE)
        } catch (_: SecurityException) {
            return@synchronized invalid("snapshot stat failed", AuthenticatedSnapshotFailureKind.IO_UNAVAILABLE)
        }
        if (length !in MIN_FILE_BYTES..maxFileBytes()) {
            return@synchronized invalid("snapshot size out of bounds", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
        }

        try {
            FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
                DataInputStream(BufferedInputStream(Channels.newInputStream(channel), BUFFER_BYTES)).use { input ->
                    val magic = ByteArray(MAGIC.size)
                    input.readFully(magic)
                    if (!MessageDigest.isEqual(magic, MAGIC)) {
                        return@synchronized invalid("snapshot magic mismatch", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
                    }

                    val version = input.readInt()
                    if (version != schemaVersion) {
                        return@synchronized invalid("snapshot schema mismatch", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
                    }

                    val payloadLength = input.readInt()
                    if (payloadLength !in 0..maxPayloadBytes) {
                        return@synchronized invalid("snapshot payload length invalid", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
                    }
                    val expectedLength = MAGIC.size.toLong() + INT_BYTES + INT_BYTES + payloadLength + MAC_BYTES
                    if (length != expectedLength) {
                        return@synchronized invalid("snapshot envelope length mismatch", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
                    }

                    val payload = ByteArray(payloadLength)
                    input.readFully(payload)
                    val expectedMac = ByteArray(MAC_BYTES)
                    input.readFully(expectedMac)
                    if (input.read() != -1) {
                        return@synchronized invalid("snapshot trailing bytes", AuthenticatedSnapshotFailureKind.FORMAT_INVALID)
                    }

                    val actualMac = try {
                        computeMac(activeKey, version, payload)
                    } catch (_: GeneralSecurityException) {
                        return@synchronized invalid("snapshot key operation failed", AuthenticatedSnapshotFailureKind.KEY_OPERATION)
                    } catch (_: ProviderException) {
                        return@synchronized invalid("snapshot key operation failed", AuthenticatedSnapshotFailureKind.KEY_OPERATION)
                    } catch (_: RuntimeException) {
                        // Mac.init()/doFinal() on OEM AndroidKeyStore providers may surface provider
                        // faults as unchecked exceptions. Keep those separate from file integrity.
                        return@synchronized invalid("snapshot key operation failed", AuthenticatedSnapshotFailureKind.KEY_OPERATION)
                    }
                    if (!MessageDigest.isEqual(actualMac, expectedMac)) {
                        return@synchronized invalid("snapshot authentication failed", AuthenticatedSnapshotFailureKind.AUTHENTICATION_FAILED)
                    }
                    AuthenticatedSnapshotRead(AuthenticatedSnapshotState.VALID, payload)
                }
            }
        } catch (_: IOException) {
            invalid("snapshot read failed", AuthenticatedSnapshotFailureKind.IO_UNAVAILABLE)
        } catch (_: SecurityException) {
            invalid("snapshot read failed", AuthenticatedSnapshotFailureKind.IO_UNAVAILABLE)
        } catch (_: RuntimeException) {
            invalid("snapshot runtime failure", AuthenticatedSnapshotFailureKind.RUNTIME_FAILURE)
        }
    }

    /**
     * Parses the fixed snapshot envelope without evaluating its HMAC.
     *
     * This is intentionally dangerous and exists only for one recovery case: callers that hold an
     * independently authenticated inner AEAD envelope may recover that ciphertext when a historical
     * OEM AndroidKeyStore HMAC becomes unusable after an app update. Returned bytes are UNTRUSTED
     * until the caller authenticates/decrypts them independently. Plaintext callers must never use
     * this method as an integrity bypass.
     */
    fun readPayloadWithoutAuthenticationForAeadRecovery(): ByteArray? = synchronized(lock) {
        val path = file.toPath()
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) return@synchronized null
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return@synchronized null
        val length = try {
            Files.size(path)
        } catch (_: IOException) {
            return@synchronized null
        } catch (_: SecurityException) {
            return@synchronized null
        }
        if (length !in MIN_FILE_BYTES..maxFileBytes()) return@synchronized null

        try {
            FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
                DataInputStream(BufferedInputStream(Channels.newInputStream(channel), BUFFER_BYTES)).use { input ->
                    val magic = ByteArray(MAGIC.size)
                    input.readFully(magic)
                    if (!MessageDigest.isEqual(magic, MAGIC)) return@synchronized null
                    val version = input.readInt()
                    if (version != schemaVersion) return@synchronized null
                    val payloadLength = input.readInt()
                    if (payloadLength !in 0..maxPayloadBytes) return@synchronized null
                    val expectedLength = MAGIC.size.toLong() + INT_BYTES + INT_BYTES + payloadLength + MAC_BYTES
                    if (length != expectedLength) return@synchronized null
                    val payload = ByteArray(payloadLength)
                    input.readFully(payload)
                    val ignoredMac = ByteArray(MAC_BYTES)
                    input.readFully(ignoredMac)
                    if (input.read() != -1) {
                        payload.fill(0)
                        return@synchronized null
                    }
                    payload
                }
            }
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        } catch (_: RuntimeException) {
            null
        }
    }

    @Throws(IOException::class)
    fun write(payload: ByteArray) = synchronized(lock) {
        val activeKey = try {
            resolveKey()
        } catch (error: Exception) {
            throw IOException("snapshot key operation failed", error)
        }
        if (activeKey == null) throw IOException("snapshot key unavailable")
        require(payload.size <= maxPayloadBytes) { "snapshot payload exceeds limit" }
        val parent = file.parentFile ?: throw IOException("snapshot parent missing")
        val parentPath = parent.toPath()
        if (!Files.exists(parentPath, LinkOption.NOFOLLOW_LINKS)) Files.createDirectories(parentPath)
        if (Files.isSymbolicLink(parentPath) || !Files.isDirectory(parentPath, LinkOption.NOFOLLOW_LINKS)) {
            throw IOException("snapshot parent is not a trusted directory")
        }
        val targetPath = file.toPath()
        if (Files.exists(targetPath, LinkOption.NOFOLLOW_LINKS) &&
            (Files.isSymbolicLink(targetPath) || !Files.isRegularFile(targetPath, LinkOption.NOFOLLOW_LINKS))) {
            throw IOException("snapshot target is not a regular file")
        }

        val suffix = ByteArray(8).also(random::nextBytes).toHex()
        val temp = File(parent, ".${file.name}.$suffix.tmp")
        try {
            val mac = try {
                computeMac(activeKey, schemaVersion, payload)
            } catch (error: GeneralSecurityException) {
                throw IOException("snapshot key operation failed", error)
            } catch (error: ProviderException) {
                throw IOException("snapshot key operation failed", error)
            } catch (error: RuntimeException) {
                throw IOException("snapshot key operation failed", error)
            }
            FileChannel.open(temp.toPath(), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                val output = DataOutputStream(BufferedOutputStream(Channels.newOutputStream(channel), BUFFER_BYTES))
                output.write(MAGIC)
                output.writeInt(schemaVersion)
                output.writeInt(payload.size)
                output.write(payload)
                output.write(mac)
                output.flush()
                channel.force(true)
            }
            val staged = AuthenticatedSnapshotStore(temp, activeKey, schemaVersion, maxPayloadBytes).read()
            if (staged.state != AuthenticatedSnapshotState.VALID || staged.payload == null || !MessageDigest.isEqual(staged.payload, payload)) {
                throw IOException("snapshot staged verification failed")
            }
            DurableAtomicFiles.replace(temp, file)
            val verify = read()
            if (verify.state != AuthenticatedSnapshotState.VALID || verify.payload == null || !MessageDigest.isEqual(verify.payload, payload)) {
                throw IOException("snapshot post-write verification failed")
            }
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    fun clear(): Boolean = synchronized(lock) {
        val activeKey = try {
            resolveKey()
        } catch (_: Exception) {
            null
        }
        if (activeKey == null) return@synchronized false
        try {
            Files.deleteIfExists(file.toPath())
            true
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        }
    }

    fun path(): File = file

    @Throws(GeneralSecurityException::class)
    private fun resolveKey(): SecretKey? = try {
        keyProvider?.invoke() ?: key
    } catch (error: GeneralSecurityException) {
        throw error
    } catch (error: ProviderException) {
        throw GeneralSecurityException("snapshot key provider failed", error)
    } catch (error: RuntimeException) {
        throw GeneralSecurityException("snapshot key provider failed", error)
    }

    @Throws(GeneralSecurityException::class)
    private fun computeMac(activeKey: SecretKey, version: Int, payload: ByteArray): ByteArray {
        return BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.update(MAC_DOMAIN)
            mac.update(MAGIC)
            mac.update(intBytes(version))
            mac.update(intBytes(payload.size))
            mac.update(payload)
            mac.doFinal()
        }
    }

    private fun maxFileBytes(): Long = MAGIC.size.toLong() + INT_BYTES + INT_BYTES + maxPayloadBytes + MAC_BYTES

    private fun invalid(reason: String, failureKind: AuthenticatedSnapshotFailureKind) = AuthenticatedSnapshotRead(
        state = AuthenticatedSnapshotState.INVALID,
        reason = reason,
        failureKind = failureKind,
    )

    private fun intBytes(value: Int): ByteArray = byteArrayOf(
        (value ushr 24).toByte(),
        (value ushr 16).toByte(),
        (value ushr 8).toByte(),
        value.toByte(),
    )

    private fun ByteArray.toHex(): String = buildString(size * 2) {
        for (byte in this@toHex) {
            val value = byte.toInt() and 0xff
            append(HEX[value ushr 4])
            append(HEX[value and 0x0f])
        }
    }

    companion object {
        private val MAGIC = "VGTAST01".toByteArray(StandardCharsets.US_ASCII)
        private val MAC_DOMAIN = "VisionGaiaTechnology/AuthenticatedSnapshotStore/v1\u0000".toByteArray(StandardCharsets.US_ASCII)
        private const val MAC_BYTES = 32
        private const val INT_BYTES = 4L
        private const val BUFFER_BYTES = 16 * 1024
        private const val MAX_PAYLOAD_LIMIT = 16 * 1024 * 1024
        private val MIN_FILE_BYTES = MAGIC.size.toLong() + INT_BYTES + INT_BYTES + MAC_BYTES
        private val HEX = "0123456789abcdef".toCharArray()
    }
}
