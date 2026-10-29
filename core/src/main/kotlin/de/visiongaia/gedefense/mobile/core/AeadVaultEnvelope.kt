package de.visiongaia.gedefense.mobile.core

import java.io.ByteArrayOutputStream
import java.io.DataOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.GeneralSecurityException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

// STATUS: DIAMANT VGT SUPREME
/**
 * Binary AES-256-GCM envelope used by Android's Secure Telemetry Vault.
 *
 * The codec is Android-independent so its parsing, AAD binding and tamper behavior can be tested
 * on the JVM. Key custody is deliberately outside this class. Active Android generations normally
 * pass software-derived domain keys, while the bounded opaque-key gate still protects legacy or
 * provider-backed SecretKey implementations.
 */
object AeadVaultEnvelope {
    data class Opened(val plaintext: ByteArray, val keyVersion: Int)

    private val magic = "VGTVLT01".toByteArray(StandardCharsets.US_ASCII)
    private val aadDomain = "VisionGaiaTechnology/SecureTelemetryVault/v1\u0000".toByteArray(StandardCharsets.US_ASCII)
    private val bindingPattern = Regex("[A-Za-z0-9._/-]{1,160}")

    const val ENVELOPE_OVERHEAD_BYTES = 56
    private const val FORMAT_VERSION = 1
    private const val NONCE_BYTES = 12
    private const val GCM_TAG_BITS = 128
    private const val GCM_TAG_BYTES = GCM_TAG_BITS / 8

    fun isEnvelope(bytes: ByteArray): Boolean {
        if (bytes.size < ENVELOPE_OVERHEAD_BYTES) return false
        var diff = 0
        for (i in magic.indices) diff = diff or (bytes[i].toInt() xor magic[i].toInt())
        return diff == 0
    }

    fun peekKeyVersion(envelope: ByteArray): Int? {
        if (!isEnvelope(envelope) || envelope.size < magic.size + 8) return null
        val buffer = ByteBuffer.wrap(envelope).order(ByteOrder.BIG_ENDIAN)
        buffer.position(magic.size)
        if (buffer.int != FORMAT_VERSION) return null
        return buffer.int.takeIf { it > 0 }
    }

    fun seal(
        key: SecretKey,
        domain: String,
        binding: String,
        schemaVersion: Int,
        keyVersion: Int,
        plaintext: ByteArray,
        random: SecureRandom = SecureRandom(),
    ): ByteArray {
        validate(domain, binding, schemaVersion, keyVersion, plaintext.size)
        require(key.algorithm.equals("AES", ignoreCase = true)) { "vault key must be AES" }
        val nonce = ByteArray(NONCE_BYTES).also(random::nextBytes)
        val ciphertextBytes = Math.addExact(plaintext.size, GCM_TAG_BYTES)
        val aad = aad(domain, binding, schemaVersion, keyVersion, plaintext.size, ciphertextBytes)
        try {
            val ciphertext = BoundedSecretKeyCrypto.execute(key) {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(plaintext)
            }
            check(ciphertext.size == ciphertextBytes) { "unexpected AES-GCM output size" }
            return ByteArrayOutputStream(ENVELOPE_OVERHEAD_BYTES + plaintext.size).use { bytes ->
                DataOutputStream(bytes).use { output ->
                    output.write(magic)
                    output.writeInt(FORMAT_VERSION)
                    output.writeInt(keyVersion)
                    output.writeInt(schemaVersion)
                    output.writeInt(plaintext.size)
                    output.writeInt(ciphertext.size)
                    output.write(nonce)
                    output.write(ciphertext)
                    output.flush()
                }
                bytes.toByteArray()
            }.also { ciphertext.fill(0) }
        } finally {
            nonce.fill(0)
            aad.fill(0)
        }
    }

    @Throws(GeneralSecurityException::class)
    fun open(
        key: SecretKey,
        domain: String,
        binding: String,
        expectedSchemaVersion: Int,
        envelope: ByteArray,
        maxPlaintextBytes: Int,
        maxKeyVersion: Int,
    ): Opened {
        require(maxPlaintextBytes > 0) { "invalid plaintext bound" }
        require(maxKeyVersion > 0) { "invalid key-version bound" }
        require(key.algorithm.equals("AES", ignoreCase = true)) { "vault key must be AES" }
        if (!isEnvelope(envelope)) throw GeneralSecurityException("vault envelope magic mismatch")

        val buffer = ByteBuffer.wrap(envelope).order(ByteOrder.BIG_ENDIAN)
        val readMagic = ByteArray(magic.size).also(buffer::get)
        if (!MessageDigest.isEqual(readMagic, magic)) throw GeneralSecurityException("vault magic mismatch")
        val format = buffer.int
        if (format != FORMAT_VERSION) throw GeneralSecurityException("vault format unsupported")
        val keyVersion = buffer.int
        if (keyVersion !in 1..maxKeyVersion) throw GeneralSecurityException("vault key version unsupported")
        val schemaVersion = buffer.int
        if (schemaVersion != expectedSchemaVersion) throw GeneralSecurityException("vault schema mismatch")
        val plaintextBytes = buffer.int
        if (plaintextBytes !in 0..maxPlaintextBytes) throw GeneralSecurityException("vault plaintext length invalid")
        val ciphertextBytes = buffer.int
        if (ciphertextBytes != plaintextBytes + GCM_TAG_BYTES) throw GeneralSecurityException("vault ciphertext length invalid")
        if (envelope.size != ENVELOPE_OVERHEAD_BYTES + plaintextBytes) throw GeneralSecurityException("vault envelope length mismatch")
        if (buffer.remaining() != NONCE_BYTES + ciphertextBytes) throw GeneralSecurityException("vault remaining length invalid")

        val nonce = ByteArray(NONCE_BYTES).also(buffer::get)
        val ciphertext = ByteArray(ciphertextBytes).also(buffer::get)
        if (buffer.hasRemaining()) throw GeneralSecurityException("vault trailing bytes")
        val aad = aad(domain, binding, schemaVersion, keyVersion, plaintextBytes, ciphertextBytes)
        try {
            val plaintext = BoundedSecretKeyCrypto.execute(key) {
                val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, nonce))
                cipher.updateAAD(aad)
                cipher.doFinal(ciphertext)
            }
            if (plaintext.size != plaintextBytes) {
                plaintext.fill(0)
                throw GeneralSecurityException("vault plaintext length mismatch")
            }
            return Opened(plaintext, keyVersion)
        } catch (badTag: AEADBadTagException) {
            throw GeneralSecurityException("vault authentication failed", badTag)
        } finally {
            nonce.fill(0)
            ciphertext.fill(0)
            aad.fill(0)
        }
    }

    private fun validate(domain: String, binding: String, schemaVersion: Int, keyVersion: Int, plaintextBytes: Int) {
        require(domain.matches(Regex("[a-z0-9-]{3,64}"))) { "invalid vault domain" }
        require(bindingPattern.matches(binding)) { "invalid vault binding" }
        require(schemaVersion > 0) { "invalid vault schema" }
        require(keyVersion > 0) { "invalid vault key version" }
        require(plaintextBytes >= 0) { "invalid vault plaintext size" }
    }

    private fun aad(
        domain: String,
        binding: String,
        schemaVersion: Int,
        keyVersion: Int,
        plaintextBytes: Int,
        ciphertextBytes: Int,
    ): ByteArray {
        val domainBytes = domain.toByteArray(StandardCharsets.US_ASCII)
        val bindingBytes = binding.toByteArray(StandardCharsets.US_ASCII)
        return ByteArrayOutputStream(aadDomain.size + domainBytes.size + bindingBytes.size + 32).use { bytes ->
            DataOutputStream(bytes).use { output ->
                output.write(aadDomain)
                output.writeInt(FORMAT_VERSION)
                output.writeInt(keyVersion)
                output.writeInt(schemaVersion)
                output.writeInt(plaintextBytes)
                output.writeInt(ciphertextBytes)
                output.writeInt(domainBytes.size)
                output.write(domainBytes)
                output.writeInt(bindingBytes.size)
                output.write(bindingBytes)
                output.flush()
            }
            bytes.toByteArray()
        }
    }
}
