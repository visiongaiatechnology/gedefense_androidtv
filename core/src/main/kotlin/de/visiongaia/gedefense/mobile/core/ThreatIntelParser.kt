package de.visiongaia.gedefense.mobile.core

private val SPAMHAUS_CIDR = Regex("\\\"cidr\\\"\\s*:\\s*\\\"([^\\\"]{1,80})\\\"")

data class ThreatRecord(val feedId: String, val prefix: IpPrefix, val score: Int = 1)
data class ParseResult(val records: List<ThreatRecord>, val rejected: Int, val truncated: Boolean)

object ThreatIntelParser {
    fun parse(feed: ThreatFeed, lines: Sequence<String>): ParseResult {
        val out = ArrayList<ThreatRecord>(minOf(feed.maxEntries, 8192))
        val seen = HashSet<IpPrefix>()
        var rejected = 0
        var truncated = false
        for (line in lines) {
            if (out.size >= feed.maxEntries) {
                truncated = true
                break
            }
            val candidate = when (feed.format) {
                FeedFormat.PLAIN -> firstToken(line)?.let { it to 1 }
                FeedFormat.SPAMHAUS_JSONL -> SPAMHAUS_CIDR.find(line)?.groupValues?.getOrNull(1)?.let { it to 1 }
                FeedFormat.IPSUM_SCORE -> parseIpsum(line, feed.minIpsumScore)
            } ?: continue
            val prefix = IpPrefix.parse(candidate.first)
            if (prefix == null || !IpPrefix.isPublic(prefix)) {
                rejected++
                continue
            }
            if (seen.add(prefix)) out += ThreatRecord(feed.id, prefix, candidate.second)
        }
        return ParseResult(out, rejected, truncated)
    }

    private fun firstToken(line: String): String? {
        var start = 0
        while (start < line.length && line[start].isWhitespace()) start++
        if (start >= line.length || line[start] == '#' || line[start] == ';') return null
        var end = start
        while (end < line.length && !line[end].isWhitespace()) end++
        while (end > start && (line[end - 1] == ';' || line[end - 1] == ',')) end--
        return if (end > start) line.substring(start, end) else null
    }

    private fun parseIpsum(line: String, minScore: Int): Pair<String, Int>? {
        var cursor = 0
        while (cursor < line.length && line[cursor].isWhitespace()) cursor++
        if (cursor >= line.length || line[cursor] == '#') return null
        val ipStart = cursor
        while (cursor < line.length && !line[cursor].isWhitespace()) cursor++
        val ipEnd = cursor
        while (cursor < line.length && line[cursor].isWhitespace()) cursor++
        if (cursor >= line.length) return null
        val scoreStart = cursor
        while (cursor < line.length && !line[cursor].isWhitespace()) cursor++
        val score = line.substring(scoreStart, cursor).toIntOrNull() ?: return null
        if (score < minScore) return null
        var cleanEnd = ipEnd
        while (cleanEnd > ipStart && (line[cleanEnd - 1] == ';' || line[cleanEnd - 1] == ',')) cleanEnd--
        if (cleanEnd <= ipStart) return null
        return line.substring(ipStart, cleanEnd) to score
    }
}
