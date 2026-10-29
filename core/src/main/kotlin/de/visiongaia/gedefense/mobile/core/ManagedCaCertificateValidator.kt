package de.visiongaia.gedefense.mobile.core

import java.io.ByteArrayInputStream
import java.security.MessageDigest
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.util.Date

data class ManagedCaCertificate(
    val subject: String,
    val issuer: String,
    val sha256Fingerprint: String,
    val notAfterMillis: Long,
    val encoded: ByteArray,
)

/**
 * Dependency-free validation boundary for Device-Owner managed CA installation.
 * It accepts exactly one currently-valid X.509 CA certificate and returns canonical DER bytes.
 */
object ManagedCaCertificateValidator {
    const val MAX_BYTES: Int = 128 * 1024
    private val HEX = "0123456789ABCDEF".toCharArray()

    fun inspect(inputBytes: ByteArray, nowMillis: Long = System.currentTimeMillis()): ManagedCaCertificate? {
        if (inputBytes.isEmpty() || inputBytes.size > MAX_BYTES) return null
        return try {
            val input = ByteArrayInputStream(inputBytes)
            val certificates = input.use { CertificateFactory.getInstance("X.509").generateCertificates(it) }
            if (certificates.size != 1) return null
            val cert = certificates.single() as? X509Certificate ?: return null
            if (cert.basicConstraints < 0) return null
            cert.keyUsage?.let { usage -> if (usage.size <= 5 || !usage[5]) return null }
            cert.checkValidity(Date(nowMillis))
            val encoded = cert.encoded ?: return null
            if (encoded.isEmpty() || encoded.size > MAX_BYTES) return null
            ManagedCaCertificate(
                subject = cert.subjectX500Principal.name,
                issuer = cert.issuerX500Principal.name,
                sha256Fingerprint = sha256HexColon(encoded),
                notAfterMillis = cert.notAfter.time,
                encoded = encoded.copyOf(),
            )
        } catch (_: Exception) {
            null
        }
    }

    private fun sha256HexColon(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        val out = CharArray(digest.size * 3 - 1)
        var cursor = 0
        for (i in digest.indices) {
            val value = digest[i].toInt() and 0xff
            out[cursor++] = HEX[value ushr 4]
            out[cursor++] = HEX[value and 0x0f]
            if (i != digest.lastIndex) out[cursor++] = ':'
        }
        return String(out)
    }
}
