package de.visiongaia.gedefense.tv.data

import android.content.Context
import android.util.Log
import de.visiongaia.gedefense.mobile.core.DurableAtomicFiles
import java.io.File
import java.io.FileOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.StandardCopyOption
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Domain-separated in-memory keys derived from the Keystore-protected keyring root. */
data class TvKeyMaterial(
    val evidenceHmac: SecretKey,
    val evidenceAes: SecretKey,
    val threatIntelHmac: SecretKey,
    val geoHmac: SecretKey,
)

/**
 * Root key custody for the TV app's local security stores.
 *
 * Design (same idea as the mobile dossier's telemetry vault): one random 256-bit root is generated on
 * first use, encrypted at rest with an Android Keystore AES-256-GCM key (StrongBox when available) and
 * stored as a small wrapped blob in `noBackupFilesDir`. Domain-separated HMAC/AES subkeys are derived
 * from that root in memory.
 *
 * Why software subkeys instead of using Keystore keys for every record: the vendored core's
 * [de.visiongaia.gedefense.mobile.core.BoundedSecretKeyCrypto] routes opaque (non-exportable) keys
 * through a single-slot executor. Its back-to-back `execute` calls can transiently be rejected while
 * the worker is between tasks, which aborted evidence verification on a real TV image. Subkeys are
 * cheap, never leave the process, and stay protected at rest by the Keystore-wrapped root, so ledger
 * and cache operations become deterministic while key custody remains hardware-backed.
 */
object TvKeyCustody {
    private const val TAG = "GeDefenseTv"
    private const val KEK_ALIAS = "vgt.gedefense.tv.evidence.kek.v1"
    private const val KEYRING_FILE = "keyring.v1"
    private const val ROOT_BYTES = 32
    private const val MAX_KEYRING_BYTES = 4096
    private const val TAG_BYTES = 16
    private const val MIN_IV_BYTES = 12
    private const val MAX_IV_BYTES = 16
    private val AAD = "vgt.gedefense.tv.keyring.v1".toByteArray(StandardCharsets.US_ASCII)

    data class Bootstrap(
        val material: TvKeyMaterial?,
        val failureCode: String?,
        /** True when this call created the keyring, i.e. any existing ledger used the legacy scheme. */
        val createdNow: Boolean,
    )

    private val lock = Any()

    @Volatile
    private var cached: TvKeyMaterial? = null

    /** Current process key material, or null while key custody is not established. */
    fun cached(): TvKeyMaterial? = cached

    /**
     * Deletes the wrapped keyring after the user asked to remove local evidence.
     *
     * Only called from the evidence `clear()` recovery path: dropping the root makes the previous
     * ledger ciphertext unreadable and allows a fresh keyring to be created on the next start (for
     * example after an Android Keystore reset made the old wrapping key unrecoverable).
     */
    fun deleteKeyring(context: Context): Boolean = try {
        synchronized(lock) {
            cached = null
            val keyring = File(File(context.applicationContext.noBackupFilesDir, "evidence"), KEYRING_FILE)
            !keyring.exists() || keyring.delete()
        }
    } catch (_: Throwable) {
        false
    }

    fun ensureLoaded(context: Context): Bootstrap = synchronized(lock) {
        cached?.let { return Bootstrap(it, null, createdNow = false) }
        val appContext = context.applicationContext
        val keyring = File(File(appContext.noBackupFilesDir, "evidence"), KEYRING_FILE)
        val existed = keyring.isFile
        return try {
            val root = if (existed) {
                unwrapRoot(appContext, keyring) ?: return Bootstrap(null, CODE_UNRECOVERABLE, createdNow = false)
            } else {
                val fresh = ByteArray(ROOT_BYTES).also { SecureRandom().nextBytes(it) }
                writeRoot(appContext, keyring, wrapRoot(appContext, fresh))
                fresh
            }
            val material = deriveMaterial(root)
            root.fill(0)
            cached = material
            Bootstrap(material, null, createdNow = !existed)
        } catch (error: Throwable) {
            Log.w(TAG, "key custody unavailable: ${describe(error)}")
            Bootstrap(null, CODE_CUSTODY_UNAVAILABLE, createdNow = false)
        }
    }

    private fun deriveMaterial(root: ByteArray): TvKeyMaterial = TvKeyMaterial(
        evidenceHmac = SecretKeySpec(derive(root, "evidence-hmac-v1"), "HmacSHA256"),
        evidenceAes = SecretKeySpec(derive(root, "evidence-aes-v1"), "AES"),
        threatIntelHmac = SecretKeySpec(derive(root, "threatintel-hmac-v1"), "HmacSHA256"),
        geoHmac = SecretKeySpec(derive(root, "geo-integrity-v1"), "HmacSHA256"),
    )

    private fun derive(root: ByteArray, label: String): ByteArray {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(root)
        digest.update(label.toByteArray(StandardCharsets.US_ASCII))
        return digest.digest()
    }

    private fun wrapRoot(context: Context, root: ByteArray): ByteArray {
        val kek = AndroidSecrets.aes256GcmOrNull(KEK_ALIAS) ?: error("keystore wrapping key unavailable")
        return AndroidKeystoreGate.call {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, kek)
            cipher.updateAAD(AAD)
            val iv = cipher.iv ?: error("AES-GCM provider returned no nonce")
            if (iv.size !in MIN_IV_BYTES..MAX_IV_BYTES) error("invalid keyring nonce")
            val ciphertext = cipher.doFinal(root)
            ByteArray(1 + iv.size + ciphertext.size).also { output ->
                output[0] = iv.size.toByte()
                System.arraycopy(iv, 0, output, 1, iv.size)
                System.arraycopy(ciphertext, 0, output, 1 + iv.size, ciphertext.size)
            }
        }
    }

    private fun unwrapRoot(context: Context, keyring: File): ByteArray? {
        val path = keyring.toPath()
        if (Files.isSymbolicLink(path) || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) return null
        val length = keyring.length()
        if (length !in (1 + MIN_IV_BYTES + TAG_BYTES + ROOT_BYTES).toLong()..MAX_KEYRING_BYTES.toLong()) return null
        val wrapped = keyring.readBytes()
        if (wrapped.size < 1 + MIN_IV_BYTES + TAG_BYTES + ROOT_BYTES) return null
        val ivLength = wrapped[0].toInt() and 0xff
        if (ivLength !in MIN_IV_BYTES..MAX_IV_BYTES) return null
        if (wrapped.size < 1 + ivLength + TAG_BYTES + ROOT_BYTES) return null
        val iv = wrapped.copyOfRange(1, 1 + ivLength)
        val ciphertext = wrapped.copyOfRange(1 + ivLength, wrapped.size)
        val kek = AndroidSecrets.aes256GcmOrNull(KEK_ALIAS) ?: return null
        val root = try {
            AndroidKeystoreGate.call {
                val cipher = Cipher.getInstance(TRANSFORMATION)
                cipher.init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(TAG_BYTES * 8, iv))
                cipher.updateAAD(AAD)
                cipher.doFinal(ciphertext)
            }
        } catch (error: Throwable) {
            Log.w(TAG, "keyring unwrap failed: ${describe(error)}")
            return null
        } finally {
            iv.fill(0)
        }
        if (root.size != ROOT_BYTES) {
            root.fill(0)
            return null
        }
        return root
    }

    private fun writeRoot(context: Context, keyring: File, wrapped: ByteArray) {
        val parent = keyring.parentFile ?: error("keyring parent missing")
        if (!parent.mkdirs() && !parent.isDirectory) error("keyring directory unavailable")
        val temp = Files.createTempFile(parent.toPath(), ".${KEYRING_FILE}.tmp-", ".tmp").toFile()
        try {
            FileOutputStream(temp, false).use { output ->
                output.write(wrapped)
                output.fd.sync()
            }
            if (temp.length() != wrapped.size.toLong()) error("keyring write verification failed")
            DurableAtomicFiles.replace(temp, keyring)
        } finally {
            if (temp.exists()) temp.delete()
        }
    }

    private fun describe(error: Throwable): String {
        val message = error.message.orEmpty()
            .map { character -> if (character == '\n' || character == '\r') ' ' else character }
            .joinToString("")
            .trim()
            .take(120)
        return "${error::class.java.simpleName}: $message"
    }

    private const val TRANSFORMATION = "AES/GCM/NoPadding"
    const val CODE_CUSTODY_UNAVAILABLE = "evidence_key_custody_unavailable"
    const val CODE_UNRECOVERABLE = "evidence_key_unrecoverable"
}
