package de.visiongaia.gedefense.mobile.core

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.SecretKey

data class CachedFeedInfo(
    val fetchedAt: Long,
    val records: Int,
    val bytes: Long,
    val generation: String,
    val fresh: Boolean,
)

data class FeedCommitResult(
    val ok: Boolean,
    val message: String,
    val records: Int = 0,
)

/**
 * Crash-tolerant, authenticated on-device feed cache.
 *
 * A generation is valid only when a feed file and HMAC-authenticated metadata file form a verified pair.
 * There is no mutable active pointer. Partial generations are ignored, preserving the previous valid generation.
 */
class ThreatCacheStore(
    private val root: File,
    private val integrityKey: SecretKey?,
    private val integrityKeyProvider: (() -> SecretKey?)? = null,
) {
    private val lock = Any()

    init {
        require(root.path.isNotBlank())
    }

    fun loadSnapshot(now: Long = System.currentTimeMillis()): ThreatIndex = synchronized(lock) {
        if (activeIntegrityKey() == null) return@synchronized ThreatIndex.empty()
        ensureRoot()
        val builder = ThreatIndex.Builder()
        for (feed in ThreatFeedCatalog.all) {
            val generation = newestValidGeneration(feed) ?: continue
            if (!isFresh(feed, generation.meta, now)) continue
            val parsed = parseFile(feed, generation.data)
            if (!parsed.truncated) builder.addAll(parsed.records)
        }
        builder.build()
    }

    fun latestInfo(feed: ThreatFeed, now: Long = System.currentTimeMillis()): CachedFeedInfo? = synchronized(lock) {
        if (activeIntegrityKey() == null) return@synchronized null
        ensureRoot()
        newestValidGeneration(feed)?.let { generation ->
            CachedFeedInfo(
                generation.meta.fetchedAt,
                generation.meta.records,
                generation.meta.bytes,
                generation.meta.generation,
                isFresh(feed, generation.meta, now),
            )
        }
    }

    fun commit(
        feed: ThreatFeed,
        downloaded: File,
        expectedSha256: String,
        expectedBytes: Long,
        fetchedAt: Long = System.currentTimeMillis(),
    ): FeedCommitResult = synchronized(lock) {
        if (activeIntegrityKey() == null) return@synchronized FeedCommitResult(false, "integrity key unavailable")
        ensureRoot()
        if (!downloaded.isFile) return FeedCommitResult(false, "downloaded feed missing")
        if (expectedBytes !in 1..feed.maxDownloadBytes || downloaded.length() != expectedBytes) {
            return FeedCommitResult(false, "downloaded feed size mismatch")
        }
        if (!expectedSha256.matches(HEX_64)) return FeedCommitResult(false, "invalid expected SHA-256")
        if (!MessageDigest.isEqual(sha256(downloaded).toByteArray(), expectedSha256.toByteArray())) {
            return FeedCommitResult(false, "downloaded feed hash mismatch")
        }
        val now = System.currentTimeMillis()
        if (fetchedAt <= 0 || fetchedAt > now + MAX_CLOCK_SKEW_MS) {
            return FeedCommitResult(false, "invalid feed timestamp")
        }

        val parsed = parseFile(feed, downloaded)
        if (parsed.records.isEmpty()) return FeedCommitResult(false, "feed produced no usable public prefixes")
        if (parsed.truncated) return FeedCommitResult(false, "feed entry limit exceeded")

        val previous = newestValidGeneration(feed)
        if (previous != null && previous.meta.records >= 200 && parsed.records.size < previous.meta.records / 5) {
            return FeedCommitResult(false, "anomalous feed shrink refused")
        }

        val generation = newGenerationId(fetchedAt)
        val unsigned = Meta(
            fetchedAt = fetchedAt,
            sha256 = expectedSha256,
            records = parsed.records.size,
            url = feed.url,
            generation = generation,
            bytes = expectedBytes,
            mac = "",
        )
        val signed = unsigned.copy(mac = mac(unsigned.payload()))
        val dataTemp = Files.createTempFile(root.toPath(), ".${feed.id}-$generation.feed-", ".tmp").toFile()
        val metaTemp = Files.createTempFile(root.toPath(), ".${feed.id}-$generation.meta-", ".tmp").toFile()
        val finalData = dataFile(feed, generation)
        val finalMeta = metaFile(feed, generation)

        return try {
            copyAndSync(downloaded, dataTemp)
            FileOutputStream(metaTemp).use {
                it.write(signed.encode().toByteArray(Charsets.UTF_8))
                it.fd.sync()
            }
            if (!MessageDigest.isEqual(sha256(dataTemp).toByteArray(), expectedSha256.toByteArray())) {
                error("staged feed hash mismatch")
            }
            val stagedMeta = readMeta(feed, metaTemp, enforceCanonicalName = false)
                ?: error("staged feed metadata failed verification")
            if (stagedMeta != signed) error("staged feed metadata mismatch")

            DurableAtomicFiles.replace(dataTemp, finalData)
            DurableAtomicFiles.replace(metaTemp, finalMeta)

            val committed = readAndValidateGeneration(feed, finalMeta)
                ?: error("committed generation failed verification")
            if (committed.meta.sha256 != expectedSha256 || committed.meta.records != parsed.records.size) {
                error("committed generation metadata mismatch")
            }

            pruneOldGenerations(feed, MAX_GENERATIONS_PER_FEED)
            FeedCommitResult(true, "updated", parsed.records.size)
        } catch (t: Throwable) {
            // Readers only trust complete authenticated pairs. Remove an incomplete generation if possible.
            if (readAndValidateGeneration(feed, finalMeta) == null) {
                finalMeta.delete()
                finalData.delete()
            }
            FeedCommitResult(false, t.message ?: "cache commit failed")
        } finally {
            dataTemp.delete()
            metaTemp.delete()
            cleanupTemps(feed)
        }
    }

    private data class Generation(val meta: Meta, val data: File, val metaFile: File)

    private data class Meta(
        val fetchedAt: Long,
        val sha256: String,
        val records: Int,
        val url: String,
        val generation: String,
        val bytes: Long,
        val mac: String,
    ) {
        fun payload() = "v2|$fetchedAt|$sha256|$records|$url|$generation|$bytes"
        fun encode() = buildString {
            append("version=2\n")
            append("fetched_at=$fetchedAt\n")
            append("sha256=$sha256\n")
            append("records=$records\n")
            append("url=$url\n")
            append("generation=$generation\n")
            append("bytes=$bytes\n")
            append("mac=$mac\n")
        }
    }

    private fun newestValidGeneration(feed: ThreatFeed): Generation? {
        val prefix = "${feed.id}-"
        val candidates = boundedRootFiles()
            ?.filter { file -> isRegularFileNoFollow(file) && file.name.startsWith(prefix) && file.name.endsWith(".meta") && file.length() <= MAX_META_BYTES }
            ?.sortedByDescending { it.lastModified() }
            ?.take(MAX_GENERATION_SCAN)
            ?: return null

        var newest: Generation? = null
        for (metaFile in candidates) {
            val generation = readAndValidateGeneration(feed, metaFile) ?: continue
            val current = newest
            if (current == null || generation.meta.fetchedAt > current.meta.fetchedAt) newest = generation
        }
        return newest
    }

    private fun readAndValidateGeneration(feed: ThreatFeed, metaFile: File): Generation? {
        val meta = readMeta(feed, metaFile) ?: return null
        val data = dataFile(feed, meta.generation)
        if (!isRegularFileNoFollow(data) || data.length() != meta.bytes || data.length() > feed.maxDownloadBytes) return null
        val actualHash = sha256(data)
        if (!MessageDigest.isEqual(actualHash.toByteArray(), meta.sha256.toByteArray())) return null
        val parsed = parseFile(feed, data)
        if (parsed.truncated || parsed.records.size != meta.records || parsed.records.isEmpty()) return null
        return Generation(meta, data, metaFile)
    }

    private fun readMeta(feed: ThreatFeed, file: File, enforceCanonicalName: Boolean = true): Meta? {
        if (!isRegularFileNoFollow(file) || file.length() !in 1..MAX_META_BYTES) return null
        val fields = file.readLines(Charsets.UTF_8).mapNotNull {
            val split = it.indexOf('=')
            if (split <= 0) null else it.substring(0, split) to it.substring(split + 1)
        }.toMap()
        if (fields["version"] != "2") return null
        val meta = Meta(
            fetchedAt = fields["fetched_at"]?.toLongOrNull() ?: return null,
            sha256 = fields["sha256"] ?: return null,
            records = fields["records"]?.toIntOrNull() ?: return null,
            url = fields["url"] ?: return null,
            generation = fields["generation"] ?: return null,
            bytes = fields["bytes"]?.toLongOrNull() ?: return null,
            mac = fields["mac"] ?: return null,
        )
        val now = System.currentTimeMillis()
        if (
            meta.fetchedAt <= 0 || meta.fetchedAt > now + MAX_CLOCK_SKEW_MS ||
            meta.records !in 1..feed.maxEntries || meta.bytes !in 1..feed.maxDownloadBytes
        ) return null
        if (!meta.sha256.matches(HEX_64) || !meta.mac.matches(HEX_64) || !meta.generation.matches(GENERATION_ID)) return null
        if (meta.url != feed.url) return null
        if (enforceCanonicalName && file.name != "${feed.id}-${meta.generation}.meta") return null
        val expected = mac(meta.copy(mac = "").payload())
        if (!MessageDigest.isEqual(expected.toByteArray(), meta.mac.toByteArray())) return null
        return meta
    }

    private fun isFresh(feed: ThreatFeed, meta: Meta, now: Long): Boolean {
        val maxAge = Math.multiplyExact(feed.maxStaleMinutes, 60_000L)
        val age = now - meta.fetchedAt
        return age >= -MAX_CLOCK_SKEW_MS && age <= maxAge
    }

    private fun parseFile(feed: ThreatFeed, file: File): ParseResult =
        file.bufferedReader(Charsets.UTF_8, 16 * 1024).use { ThreatIntelParser.parse(feed, it.lineSequence()) }

    private fun dataFile(feed: ThreatFeed, generation: String) = File(root, "${feed.id}-$generation.feed")
    private fun metaFile(feed: ThreatFeed, generation: String) = File(root, "${feed.id}-$generation.meta")

    private fun newGenerationId(now: Long): String {
        val random = ByteArray(8).also { SecureRandom().nextBytes(it) }
        return now.toString(16) + "-" + random.joinToString("") { "%02x".format(it) }
    }

    private fun pruneOldGenerations(feed: ThreatFeed, keep: Int) {
        val prefix = "${feed.id}-"
        val valid = boundedRootFiles()
            ?.filter { file -> isRegularFileNoFollow(file) && file.name.startsWith(prefix) && file.name.endsWith(".meta") }
            ?.mapNotNull { readAndValidateGeneration(feed, it) }
            ?.sortedByDescending { it.meta.fetchedAt }
            ?: return
        valid.drop(keep).forEach { old ->
            old.metaFile.delete()
            old.data.delete()
        }
        cleanupOrphans(feed, valid.take(keep).map { it.meta.generation }.toSet())
    }

    private fun cleanupOrphans(feed: ThreatFeed, retained: Set<String>) {
        val prefix = "${feed.id}-"
        boundedRootFiles()?.forEach { file ->
            if (!file.isFile || !file.name.startsWith(prefix)) return@forEach
            val generation = file.name.removePrefix(prefix).substringBeforeLast('.')
            if (generation.matches(GENERATION_ID) && generation !in retained) {
                val pairMeta = metaFile(feed, generation)
                val pairData = dataFile(feed, generation)
                if (readAndValidateGeneration(feed, pairMeta) == null) {
                    pairMeta.delete()
                    pairData.delete()
                }
            }
        }
    }


    private fun boundedRootFiles(): List<File>? {
        val path = root.toPath()
        if (Files.isSymbolicLink(path) || !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) return emptyList()
        return try {
            val result = ArrayList<File>(minOf(MAX_DIRECTORY_SCAN_ENTRIES, 32))
            Files.newDirectoryStream(path).use { stream ->
                for (entry in stream) {
                    if (result.size >= MAX_DIRECTORY_SCAN_ENTRIES) return null
                    result += entry.toFile()
                }
            }
            result
        } catch (_: Exception) {
            null
        }
    }

    private fun isRegularFileNoFollow(file: File): Boolean {
        val path = file.toPath()
        return !Files.isSymbolicLink(path) && Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)
    }

    private fun cleanupTemps(feed: ThreatFeed) {
        val prefix = ".${feed.id}"
        val cutoff = System.currentTimeMillis() - TEMP_MAX_AGE_MS
        boundedRootFiles()?.forEach { file ->
            if (file.isFile && file.name.startsWith(prefix) && file.lastModified() < cutoff) file.delete()
        }
    }

    private fun ensureRoot() {
        require(root.mkdirs() || root.isDirectory) { "threat-intel cache directory unavailable" }
    }

    private fun copyAndSync(source: File, target: File) {
        FileInputStream(source).use { input ->
            FileOutputStream(target).use { output ->
                val buffer = ByteArray(16 * 1024)
                while (true) {
                    val read = input.read(buffer)
                    if (read < 0) break
                    output.write(buffer, 0, read)
                }
                output.fd.sync()
            }
        }
    }

    private fun mac(value: String): String {
        val activeKey = activeIntegrityKey() ?: throw IllegalStateException("integrity key unavailable")
        return hex(BoundedSecretKeyCrypto.execute(activeKey) {
            val mac = Mac.getInstance("HmacSHA256")
            mac.init(activeKey)
            mac.doFinal(value.toByteArray(Charsets.UTF_8))
        })
    }

    private fun activeIntegrityKey(): SecretKey? = try {
        integrityKeyProvider?.invoke() ?: integrityKey
    } catch (_: Exception) {
        null
    }

    private fun sha256(file: File): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileInputStream(file).use { input ->
            val buffer = ByteArray(8192)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return hex(digest.digest())
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    companion object {
        private const val MAX_GENERATIONS_PER_FEED = 2
        private const val MAX_GENERATION_SCAN = 8
        private const val MAX_DIRECTORY_SCAN_ENTRIES = 256
        private const val MAX_META_BYTES = 16L * 1024L
        private const val TEMP_MAX_AGE_MS = 24L * 60L * 60L * 1000L
        private const val MAX_CLOCK_SKEW_MS = 10L * 60L * 1000L
        private val HEX_64 = Regex("[0-9a-f]{64}")
        private val GENERATION_ID = Regex("[0-9a-f]{8,16}-[0-9a-f]{16}")
    }
}
