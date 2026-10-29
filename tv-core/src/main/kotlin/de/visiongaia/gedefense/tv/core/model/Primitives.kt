package de.visiongaia.gedefense.tv.core.model

/**
 * Capability state of a single local collector.
 *
 * The state describes whether the underlying platform interface can be used at all, not whether a
 * finding was produced. A supported collector with zero findings is still coverage, an unsupported
 * collector is explicitly *not* a clean result.
 */
enum class CapabilityState { SUPPORTED, PERMISSION_REQUIRED, UNSUPPORTED, FAILED }

/**
 * Honest visibility of the data behind a finding or a collector result.
 *
 * [NONE] means the app could not observe the area at all. UI and report renderers must never map
 * [NONE] or [UNAVAILABLE] to a green "clean" state.
 */
enum class DataVisibility { FULL, PARTIAL, STALE, NONE }

/** Severity of a finding. [rank] orders severities for deterministic list sorting. */
enum class Severity(val rank: Int) {
    INFO(0),
    LOW(1),
    MEDIUM(2),
    HIGH(3),
    CRITICAL(4),
}

/** Confidence in a finding given the evidence quality. */
enum class Confidence { LOW, MEDIUM, HIGH }

/** What the app recommends or did. V1 is observe/recommend only; it never auto-enforces. */
enum class PolicyAction { NONE, OBSERVE, RECOMMEND_MANUAL, ESCALATE_TO_USER }

/** Freshness/quality of the underlying data. */
enum class DataQuality { FRESH, PARTIAL, STALE, UNKNOWN }

/** XDR event classes defined by the TV datasheet (section 6.1). */
enum class EventClass {
    TV_DEVICE_STATE,
    TV_APP_INVENTORY,
    TV_USAGE_SIGNAL,
    TV_CONNECTIVITY_STATE,
    TV_TI_MATCH,
    TV_SENSOR_HEALTH,
    TV_ENFORCEMENT,
}

/** Functional collector groups. */
enum class CollectorCategory { PLATFORM, APPS, HARDENING, CONNECTIVITY, THREAT_INTEL, SENSOR_HEALTH }

/**
 * Reference to a user-facing text. tv-core stays resource-agnostic so that domain logic can be
 * unit-tested on the JVM and the Android layer can resolve the same keys through resources later.
 *
 * [args] are substituted positionally ({0}, {1}, ...) by the resolving catalog. Keys and argument
 * order are a stable contract; adding a new key is backwards compatible, changing the meaning of an
 * existing key is not.
 */
data class MessageRef(val key: String, val args: List<String> = emptyList()) {
    init {
        require(key.matches(KEY_PATTERN)) { "invalid message key: $key" }
        require(args.size <= 8) { "too many message arguments" }
        require(args.all { it.length <= 512 }) { "message argument too long" }
    }

    companion object {
        private val KEY_PATTERN = Regex("""[a-z][a-z0-9_]*(\.[a-z0-9_]+){1,7}""")
    }
}

/** Resolves [MessageRef] to display text. Implementations must never throw for unknown keys. */
interface TextCatalog {
    fun resolve(ref: MessageRef): String
}

/**
 * Fallback catalog used by domain tests and by report rendering when the UI catalog is not
 * available. It renders `key(arg0, arg1)` so missing translations stay visible instead of silently
 * disappearing.
 */
object PassthroughTextCatalog : TextCatalog {
    override fun resolve(ref: MessageRef): String =
        if (ref.args.isEmpty()) ref.key else "${ref.key}(${ref.args.joinToString(", ")})"
}

/** Clamps an arbitrary score into the inclusive 0..100 range. */
fun clampScore(value: Int): Int = value.coerceIn(0, 100)
