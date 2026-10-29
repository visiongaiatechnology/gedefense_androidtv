package de.visiongaia.gedefense.tv.data

import de.visiongaia.gedefense.mobile.core.ThreatFeed
import java.io.File
import java.io.FileOutputStream
import java.net.Proxy
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/** A verified feed download in an app-private temp file. Callers must delete the file afterwards. */
data class DownloadedFeed(val file: File, val sha256: String, val bytes: Long)

/**
 * TLS-only threat-intel feed downloader.
 *
 * Ported from the GeDefense mobile dossier. Hard guarantees:
 *  - HTTPS only, no proxy, no user-info/fragment in the URL, no cleartext fallback;
 *  - redirects are not followed automatically: at most [MAX_REDIRECTS] manual hops, each one must stay
 *    on the original host and use HTTPS;
 *  - declared and streamed size are both capped by the feed's own `maxDownloadBytes`;
 *  - HTML/XHTML responses are refused so a captive portal or error page can never become feed data;
 *  - every line is capped to keep parsing memory bounded;
 *  - the SHA-256 digest is computed while streaming and verified again by the cache store on commit.
 */
object TvFeedDownloader {
    private const val MAX_LINE_BYTES = 8192
    private const val CONNECT_TIMEOUT_MS = 10_000
    private const val READ_TIMEOUT_MS = 15_000
    private const val MAX_REDIRECTS = 2
    private const val MAX_LINE_SCAN_CHUNK = 16 * 1024

    @Throws(InterruptedException::class)
    fun download(feed: ThreatFeed, dir: File): DownloadedFeed {
        throwIfInterrupted()
        require(dir.mkdirs() || dir.isDirectory) { "threat-intel cache directory unavailable" }
        val original = URL(feed.url)
        require(original.protocol == "https" && original.userInfo == null && original.ref == null) {
            "feed URL must be plain HTTPS"
        }

        var current = original
        var redirects = 0
        while (true) {
            throwIfInterrupted()
            val connection = (current.openConnection(Proxy.NO_PROXY) as? HttpsURLConnection)
                ?: error("HTTPS connection required")
            connection.instanceFollowRedirects = false
            connection.connectTimeout = CONNECT_TIMEOUT_MS
            connection.readTimeout = READ_TIMEOUT_MS
            connection.useCaches = false
            connection.setRequestProperty("User-Agent", "VGT-GeDefense-TV/0.1 threat-intel")
            connection.setRequestProperty(
                "Accept",
                "text/plain, application/json;q=0.9, text/json;q=0.9, application/octet-stream;q=0.5",
            )

            try {
                val code = connection.responseCode
                if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                    val location = connection.getHeaderField("Location") ?: error("redirect without location")
                    if (++redirects > MAX_REDIRECTS) error("too many redirects")
                    val next = URL(current, location)
                    require(
                        next.protocol == "https" &&
                            next.host.equals(original.host, ignoreCase = true) &&
                            next.userInfo == null && next.ref == null,
                    ) { "cross-host or insecure redirect refused" }
                    current = next
                    continue
                }
                if (code != HttpsURLConnection.HTTP_OK) error("feed HTTP $code")

                val mediaType = connection.contentType
                    ?.substringBefore(';')
                    ?.trim()
                    ?.lowercase()
                    .orEmpty()
                if (mediaType == "text/html" || mediaType == "application/xhtml+xml") {
                    error("HTML response refused")
                }

                val declaredLength = connection.contentLengthLong
                if (declaredLength > feed.maxDownloadBytes) error("feed exceeds size limit")

                return readBody(feed, dir, connection)
            } finally {
                connection.disconnect()
            }
        }
    }

    @Throws(InterruptedException::class)
    private fun readBody(feed: ThreatFeed, dir: File, connection: HttpsURLConnection): DownloadedFeed {
        val temp = SecureFiles.createPrivateTempFile(dir, ".${feed.id.take(48)}.download-")
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        var lineLength = 0
        try {
            connection.inputStream.use { input ->
                FileOutputStream(temp).use { output ->
                    val buffer = ByteArray(MAX_LINE_SCAN_CHUNK)
                    while (true) {
                        throwIfInterrupted()
                        val read = input.read(buffer)
                        if (read < 0) break
                        total += read
                        if (total > feed.maxDownloadBytes) error("feed exceeds size limit")
                        for (index in 0 until read) {
                            if (buffer[index].toInt() == '\n'.code) {
                                lineLength = 0
                            } else if (++lineLength > MAX_LINE_BYTES) {
                                error("feed line exceeds limit")
                            }
                        }
                        digest.update(buffer, 0, read)
                        output.write(buffer, 0, read)
                    }
                    output.fd.sync()
                }
            }
            if (total == 0L) error("empty feed")
            return DownloadedFeed(temp, hex(digest.digest()), total)
        } catch (t: Throwable) {
            temp.delete()
            throw t
        }
    }

    private fun throwIfInterrupted() {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("feed download interrupted")
    }

    private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}
