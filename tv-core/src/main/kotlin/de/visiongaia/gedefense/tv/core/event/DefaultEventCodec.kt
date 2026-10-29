package de.visiongaia.gedefense.tv.core.event

import de.visiongaia.gedefense.tv.core.model.Confidence
import de.visiongaia.gedefense.tv.core.model.DataQuality
import de.visiongaia.gedefense.tv.core.model.EventClass
import de.visiongaia.gedefense.tv.core.model.PolicyAction
import de.visiongaia.gedefense.tv.core.model.Severity
import de.visiongaia.gedefense.tv.core.model.TvEvent
import java.time.Instant
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

/**
 * Dependency-free JSONL codec for the XDR-lite [TvEvent] schema.
 *
 * Wire format:
 *  - one JSON object per line, fixed key order, schema tag `gedefense-tv-event/1`;
 *  - timestamps are canonical ISO-8601 UTC strings, attributes are sorted by key;
 *  - every string is fully escaped, so an encoded event never contains a raw newline or control
 *    character and always occupies exactly one line;
 *  - [decode] is strict: unknown/missing keys, duplicate keys, wrong types, non-canonical timestamps
 *    or values that violate the event model are rejected with `null` instead of being guessed.
 */
object DefaultEventCodec : EventCodec {

    private const val SCHEMA = "gedefense-tv-event/1"
    private const val MAX_LINE_LENGTH = 32_768
    private const val KEY_SCHEMA = "schema"
    private const val KEY_EVENT_CLASS = "event_class"
    private const val KEY_EVENT_ID = "event_id"
    private const val KEY_DEVICE_ID = "device_id"
    private const val KEY_EVENT_TIME = "event_time_utc"
    private const val KEY_COLLECTOR_ID = "collector_id"
    private const val KEY_PLATFORM = "platform"
    private const val KEY_OS_API_LEVEL = "os_api_level"
    private const val KEY_SUBJECT = "subject"
    private const val KEY_DATA_QUALITY = "data_quality"
    private const val KEY_SEVERITY = "severity"
    private const val KEY_CONFIDENCE = "confidence"
    private const val KEY_EVIDENCE_REF = "evidence_ref"
    private const val KEY_RULE_ID = "rule_id"
    private const val KEY_POLICY_ACTION = "policy_action"
    private const val KEY_FIRST_SEEN = "first_seen_utc"
    private const val KEY_LAST_SEEN = "last_seen_utc"
    private const val KEY_ATTRIBUTES = "attributes"

    private val FIELDS = listOf(
        KEY_SCHEMA,
        KEY_EVENT_CLASS,
        KEY_EVENT_ID,
        KEY_DEVICE_ID,
        KEY_EVENT_TIME,
        KEY_COLLECTOR_ID,
        KEY_PLATFORM,
        KEY_OS_API_LEVEL,
        KEY_SUBJECT,
        KEY_DATA_QUALITY,
        KEY_SEVERITY,
        KEY_CONFIDENCE,
        KEY_EVIDENCE_REF,
        KEY_RULE_ID,
        KEY_POLICY_ACTION,
        KEY_FIRST_SEEN,
        KEY_LAST_SEEN,
        KEY_ATTRIBUTES,
    )
    private val FIELD_SET: Set<String> = FIELDS.toSet()

    override fun encode(event: TvEvent): String {
        val attributes = event.attributes.entries
            .sortedBy { it.key }
            .joinToString(separator = ",", prefix = "{", postfix = "}") { (key, value) ->
                "${quote(key)}:${quote(value)}"
            }
        val fields = listOf(
            KEY_SCHEMA to quote(SCHEMA),
            KEY_EVENT_CLASS to quote(event.eventClass.name),
            KEY_EVENT_ID to quote(event.eventId),
            KEY_DEVICE_ID to quote(event.deviceId),
            KEY_EVENT_TIME to quote(formatUtc(event.eventTimeMillis)),
            KEY_COLLECTOR_ID to quote(event.collectorId),
            KEY_PLATFORM to quote(event.platform),
            KEY_OS_API_LEVEL to event.osApiLevel.toString(),
            KEY_SUBJECT to quote(event.subject),
            KEY_DATA_QUALITY to quote(event.dataQuality.name),
            KEY_SEVERITY to optionalName(event.severity),
            KEY_CONFIDENCE to optionalName(event.confidence),
            KEY_EVIDENCE_REF to optionalText(event.evidenceRef),
            KEY_RULE_ID to optionalText(event.ruleId),
            KEY_POLICY_ACTION to optionalName(event.policyAction),
            KEY_FIRST_SEEN to optionalTime(event.firstSeenMillis),
            KEY_LAST_SEEN to optionalTime(event.lastSeenMillis),
            KEY_ATTRIBUTES to attributes,
        )
        return fields.joinToString(separator = ",", prefix = "{", postfix = "}") { (key, value) ->
            "${quote(key)}:$value"
        }
    }

    override fun decode(line: String): TvEvent? {
        if (line.length > MAX_LINE_LENGTH) return null
        val document = line.trim()
        if (document.isEmpty()) return null
        val parsed = EventJsonParser(document).parseDocument() ?: return null
        if (parsed.keys != FIELD_SET) return null

        if ((parsed[KEY_SCHEMA] as? JsonValue.Text)?.value != SCHEMA) return null

        val eventClass = enumOrNull<EventClass>(text(parsed[KEY_EVENT_CLASS])) ?: return null
        val eventId = text(parsed[KEY_EVENT_ID]) ?: return null
        val deviceId = text(parsed[KEY_DEVICE_ID]) ?: return null
        val eventTimeMillis = parseUtcMillis(text(parsed[KEY_EVENT_TIME]) ?: return null) ?: return null
        val collectorId = text(parsed[KEY_COLLECTOR_ID]) ?: return null
        val platform = text(parsed[KEY_PLATFORM]) ?: return null
        val osApiLevel = number(parsed[KEY_OS_API_LEVEL])?.toIntOrNull() ?: return null
        val subject = text(parsed[KEY_SUBJECT]) ?: return null
        val dataQuality = enumOrNull<DataQuality>(text(parsed[KEY_DATA_QUALITY])) ?: return null
        val severity: Severity? = when (val raw = parsed[KEY_SEVERITY]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> enumOrNull<Severity>(raw.value) ?: return null
            else -> return null
        }
        val confidence: Confidence? = when (val raw = parsed[KEY_CONFIDENCE]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> enumOrNull<Confidence>(raw.value) ?: return null
            else -> return null
        }
        val evidenceRef: String? = when (val raw = parsed[KEY_EVIDENCE_REF]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> raw.value
            else -> return null
        }
        val ruleId: String? = when (val raw = parsed[KEY_RULE_ID]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> raw.value
            else -> return null
        }
        val policyAction: PolicyAction? = when (val raw = parsed[KEY_POLICY_ACTION]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> enumOrNull<PolicyAction>(raw.value) ?: return null
            else -> return null
        }
        val firstSeenMillis: Long? = when (val raw = parsed[KEY_FIRST_SEEN]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> parseUtcMillis(raw.value) ?: return null
            else -> return null
        }
        val lastSeenMillis: Long? = when (val raw = parsed[KEY_LAST_SEEN]) {
            is JsonValue.Null -> null
            is JsonValue.Text -> parseUtcMillis(raw.value) ?: return null
            else -> return null
        }
        val attributes = (parsed[KEY_ATTRIBUTES] as? JsonValue.Nested)?.values ?: return null

        return runCatching {
            TvEvent(
                eventClass = eventClass,
                eventId = eventId,
                deviceId = deviceId,
                eventTimeMillis = eventTimeMillis,
                collectorId = collectorId,
                platform = platform,
                osApiLevel = osApiLevel,
                subject = subject,
                dataQuality = dataQuality,
                severity = severity,
                confidence = confidence,
                evidenceRef = evidenceRef,
                ruleId = ruleId,
                policyAction = policyAction,
                firstSeenMillis = firstSeenMillis,
                lastSeenMillis = lastSeenMillis,
                attributes = attributes,
            )
        }.getOrNull()
    }

    // --- field helpers -------------------------------------------------------------------------

    private fun text(value: JsonValue?): String? = (value as? JsonValue.Text)?.value

    private fun number(value: JsonValue?): String? = (value as? JsonValue.Number)?.value

    private fun optionalName(value: Enum<*>?): String = value?.let { quote(it.name) } ?: "null"

    private fun optionalText(value: String?): String = value?.let(::quote) ?: "null"

    private fun optionalTime(millis: Long?): String = millis?.let { quote(formatUtc(it)) } ?: "null"

    private inline fun <reified T : Enum<T>> enumOrNull(value: String?): T? =
        value?.let { candidate -> runCatching { enumValueOf<T>(candidate) }.getOrNull() }

    private fun parseUtcMillis(value: String): Long? {
        val instant = try {
            Instant.parse(value)
        } catch (_: DateTimeParseException) {
            return null
        }
        val millis = instant.toEpochMilli()
        return if (formatUtc(millis) == value) millis else null
    }

    private fun formatUtc(millis: Long): String = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(millis))

    // --- JSON string escaping ------------------------------------------------------------------

    private fun quote(value: String): String {
        val out = StringBuilder(value.length + 2)
        out.append('"')
        value.forEach { character ->
            when (character) {
                '"' -> out.append("\\\"")
                '\\' -> out.append("\\\\")
                '\b' -> out.append("\\b")
                '\u000C' -> out.append("\\f")
                '\n' -> out.append("\\n")
                '\r' -> out.append("\\r")
                '\t' -> out.append("\\t")
                else -> {
                    val code = character.code
                    if (code < 0x20 || code == 0x7F) {
                        out.append("\\u").append(code.toString(16).padStart(4, '0'))
                    } else {
                        out.append(character)
                    }
                }
            }
        }
        out.append('"')
        return out.toString()
    }

    private sealed class JsonValue {
        data class Text(val value: String) : JsonValue()
        data class Number(val value: String) : JsonValue()
        data class Nested(val values: Map<String, String>) : JsonValue()
        data object Null : JsonValue()
    }

    /** Strict single-line parser for the flat event object with one nested string-only object. */
    private class EventJsonParser(private val source: String) {
        private var index = 0

        fun parseDocument(): Map<String, JsonValue>? = try {
            skipWhitespace()
            val result = parseObject()
            skipWhitespace()
            if (index == source.length) result else null
        } catch (_: IllegalArgumentException) {
            null
        }

        private fun parseObject(): LinkedHashMap<String, JsonValue> {
            expect('{')
            val result = LinkedHashMap<String, JsonValue>()
            skipWhitespace()
            if (peek() == '}') {
                index++
                return result
            }
            while (true) {
                skipWhitespace()
                val key = parseString()
                skipWhitespace()
                expect(':')
                skipWhitespace()
                val value = parseValue()
                require(result.put(key, value) == null) { "duplicate key" }
                skipWhitespace()
                when (peek()) {
                    ',' -> index++
                    '}' -> {
                        index++
                        return result
                    }
                    else -> throw IllegalArgumentException("malformed object")
                }
            }
        }

        private fun parseValue(): JsonValue = when (val current = peek()) {
            '"' -> JsonValue.Text(parseString())
            '{' -> JsonValue.Nested(parseStringMap())
            'n' -> {
                expectLiteral("null")
                JsonValue.Null
            }
            '-', in '0'..'9' -> JsonValue.Number(parseNumber())
            else -> throw IllegalArgumentException("unsupported value at $index: $current")
        }

        private fun parseStringMap(): LinkedHashMap<String, String> {
            expect('{')
            val result = LinkedHashMap<String, String>()
            skipWhitespace()
            if (peek() == '}') {
                index++
                return result
            }
            while (true) {
                skipWhitespace()
                val key = parseString()
                skipWhitespace()
                expect(':')
                skipWhitespace()
                val value = parseValue() as? JsonValue.Text
                    ?: throw IllegalArgumentException("attributes must be strings")
                require(result.put(key, value.value) == null) { "duplicate attribute" }
                skipWhitespace()
                when (peek()) {
                    ',' -> index++
                    '}' -> {
                        index++
                        return result
                    }
                    else -> throw IllegalArgumentException("malformed attributes")
                }
            }
        }

        private fun parseString(): String {
            expect('"')
            val out = StringBuilder()
            while (index < source.length) {
                val character = source[index++]
                when {
                    character == '"' -> return out.toString()
                    character == '\\' -> {
                        require(index < source.length) { "unterminated escape" }
                        when (val escape = source[index++]) {
                            '"' -> out.append('"')
                            '\\' -> out.append('\\')
                            '/' -> out.append('/')
                            'b' -> out.append('\b')
                            'f' -> out.append('\u000C')
                            'n' -> out.append('\n')
                            'r' -> out.append('\r')
                            't' -> out.append('\t')
                            'u' -> {
                                require(index + 4 <= source.length) { "truncated unicode escape" }
                                val hex = source.substring(index, index + 4)
                                require(hex.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }) {
                                    "invalid unicode escape"
                                }
                                out.append(hex.toInt(16).toChar())
                                index += 4
                            }
                            else -> throw IllegalArgumentException("invalid escape: $escape")
                        }
                    }
                    character.code < 0x20 -> throw IllegalArgumentException("raw control character")
                    else -> out.append(character)
                }
            }
            throw IllegalArgumentException("unterminated string")
        }

        private fun parseNumber(): String {
            val start = index
            if (peek() == '-') index++
            val digitStart = index
            while (index < source.length && source[index] in '0'..'9') index++
            require(index > digitStart) { "invalid number" }
            if (source[digitStart] == '0' && index - digitStart > 1) {
                throw IllegalArgumentException("leading zero in number")
            }
            return source.substring(start, index)
        }

        private fun expect(character: Char) {
            require(index < source.length && source[index] == character) {
                "expected '$character' at $index"
            }
            index++
        }

        private fun expectLiteral(literal: String) {
            require(source.startsWith(literal, index)) { "expected $literal at $index" }
            index += literal.length
        }

        private fun peek(): Char = if (index < source.length) source[index] else throw IllegalArgumentException("unexpected end")

        private fun skipWhitespace() {
            while (index < source.length && source[index] in charArrayOf(' ', '\t', '\n', '\r')) index++
        }
    }
}
