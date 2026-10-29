package de.visiongaia.gedefense.mobile.core

import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.SecretKey

data class IntegrityIdentity(
    val packageName: String,
    val versionCode: Long,
    val installSha256: String,
    val signerSha256: String,
)

data class IntegrityBaselineDecision(
    val ok: Boolean,
    val initialized: Boolean = false,
    val updated: Boolean = false,
    val reason: String? = null,
    val baseline: IntegrityIdentity? = null,
)

/** HMAC-authenticated installation identity baseline. */
class IntegrityBaselineStore(
    private val file: File,
    private val key: SecretKey?,
    private val keyProvider: (() -> SecretKey?)? = null,
    private val recoveryBoundaryMillis: Long? = null,
) {
    private val lock = Any()

    fun verifyOrAdvance(current: IntegrityIdentity): IntegrityBaselineDecision = synchronized(lock) {
        val activeKey = activeKey() ?: return@synchronized IntegrityBaselineDecision(false, reason = "integrity_key_unavailable")
        validateIdentity(current)?.let { return IntegrityBaselineDecision(false, reason = it) }
        val state = readState(file, activeKey)
        if (state == null) {
            writeState(current, activeKey)
            return IntegrityBaselineDecision(true, initialized = true, baseline = current)
        }
        if (!state.authenticated) {
            if (eligibleForUpdateKeyRecovery(file)) {
                writeState(current, activeKey)
                return IntegrityBaselineDecision(
                    ok = true,
                    initialized = true,
                    updated = true,
                    reason = "integrity_update_key_recovered",
                    baseline = current,
                )
            }
            return IntegrityBaselineDecision(false, reason = "integrity_baseline_authentication_failed")
        }
        val previous = state.identity
        if (previous.packageName != current.packageName) {
            return IntegrityBaselineDecision(false, reason = "integrity_package_identity_changed", baseline = previous)
        }
        if (!constantTimeEquals(previous.signerSha256, current.signerSha256)) {
            return IntegrityBaselineDecision(false, reason = "integrity_signer_changed", baseline = previous)
        }
        if (current.versionCode < previous.versionCode) {
            return IntegrityBaselineDecision(false, reason = "integrity_version_rollback", baseline = previous)
        }
        if (current.versionCode == previous.versionCode) {
            if (!constantTimeEquals(previous.installSha256, current.installSha256)) {
                return IntegrityBaselineDecision(false, reason = "integrity_install_hash_changed", baseline = previous)
            }
            return IntegrityBaselineDecision(true, baseline = previous)
        }

        // A forward app update is trusted only when Android presents the same signing identity.
        writeState(current, activeKey)
        IntegrityBaselineDecision(true, updated = true, baseline = current)
    }

    private fun eligibleForUpdateKeyRecovery(source: File): Boolean {
        val boundary = recoveryBoundaryMillis ?: return false
        if (boundary <= 0L || !source.isFile) return false
        val modified = source.lastModified()
        return modified in 1..boundary
    }

    private fun readState(source: File, activeKey: SecretKey): ParsedState? {
        if (!source.exists()) return null
        if (!source.isFile || source.length() !in 1..MAX_BYTES) return ParsedState.invalid()
        return try {
            val fields = source.readLines(Charsets.UTF_8).mapNotNull { line ->
                val p = line.indexOf('=')
                if (p <= 0) null else line.substring(0, p) to line.substring(p + 1)
            }.toMap()
            if (fields["format"] != "1") return ParsedState.invalid()
            val identity = IntegrityIdentity(
                packageName = fields["package"] ?: return ParsedState.invalid(),
                versionCode = fields["version_code"]?.toLongOrNull() ?: return ParsedState.invalid(),
                installSha256 = fields["install_sha256"] ?: return ParsedState.invalid(),
                signerSha256 = fields["signer_sha256"] ?: return ParsedState.invalid(),
            )
            if (validateIdentity(identity) != null) return ParsedState.invalid()
            val provided = fields["mac"] ?: return ParsedState.invalid()
            if (!provided.matches(HEX_64)) return ParsedState.invalid()
            val expected = hmac(payload(identity), activeKey)
            ParsedState(identity, constantTimeEquals(expected, provided))
        } catch (_: Exception) {
            ParsedState.invalid()
        }
    }

    private fun writeState(identity: IntegrityIdentity, activeKey: SecretKey) {
        val parent = file.parentFile ?: throw IllegalStateException("integrity baseline parent missing")
        require(parent.mkdirs() || parent.isDirectory) { "integrity baseline directory unavailable" }
        val body = buildString {
            append("format=1\n")
            append("package=").append(identity.packageName).append('\n')
            append("version_code=").append(identity.versionCode).append('\n')
            append("install_sha256=").append(identity.installSha256).append('\n')
            append("signer_sha256=").append(identity.signerSha256).append('\n')
            append("mac=").append(hmac(payload(identity), activeKey)).append('\n')
        }.toByteArray(Charsets.UTF_8)
        require(body.size <= MAX_BYTES) { "integrity baseline too large" }
        val temp = Files.createTempFile(parent.toPath(), ".${file.name.take(72)}.new-", ".tmp").toFile()
        try {
            FileOutputStream(temp).use { out -> out.write(body); out.fd.sync() }
            val staged = readState(temp, activeKey)
            if (staged == null || !staged.authenticated || staged.identity != identity) {
                throw IllegalStateException("integrity baseline staged verification failed")
            }
            DurableAtomicFiles.replace(temp, file)
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private fun validateIdentity(identity: IntegrityIdentity): String? {
        if (!identity.packageName.matches(PACKAGE_NAME)) return "integrity_invalid_package_name"
        if (identity.versionCode <= 0L) return "integrity_invalid_version"
        if (!identity.installSha256.matches(HEX_64)) return "integrity_invalid_install_hash"
        if (!identity.signerSha256.matches(HEX_64)) return "integrity_invalid_signer_hash"
        return null
    }

    private fun payload(identity: IntegrityIdentity): String =
        "v1|${identity.packageName}|${identity.versionCode}|${identity.installSha256}|${identity.signerSha256}"

    private fun hmac(value: String, activeKey: SecretKey): String =
        hex(BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.doFinal(value.toByteArray(Charsets.UTF_8))
        })

    private fun activeKey(): SecretKey? = try {
        keyProvider?.invoke() ?: key
    } catch (_: Exception) {
        null
    }

    private fun constantTimeEquals(a: String, b: String): Boolean =
        MessageDigest.isEqual(a.toByteArray(Charsets.US_ASCII), b.toByteArray(Charsets.US_ASCII))

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    private data class ParsedState(val identity: IntegrityIdentity, val authenticated: Boolean) {
        companion object {
            fun invalid() = ParsedState(IntegrityIdentity("invalid.invalid", 1, "0".repeat(64), "0".repeat(64)), false)
        }
    }

    companion object {
        private const val MAX_BYTES = 4096L
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private val PACKAGE_NAME = Regex("[A-Za-z0-9_]+(?:\\.[A-Za-z0-9_]+)+")
    }
}
