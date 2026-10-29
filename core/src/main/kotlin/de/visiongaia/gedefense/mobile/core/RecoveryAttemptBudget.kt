package de.visiongaia.gedefense.mobile.core

/**
 * Small deterministic retry/cooldown budget for local self-healing.
 *
 * The budget deliberately contains no clocks or threads. Callers supply monotonic-ish timestamps,
 * which keeps the policy testable and prevents a repair loop from becoming an availability bug.
 */
data class RecoveryBudgetDecision(
    val allowed: Boolean,
    val attemptsInWindow: Int,
    val retryAfterMillis: Long,
)

class RecoveryAttemptBudget(
    private val maxAttemptsPerWindow: Int,
    private val windowMillis: Long,
    private val cooldownMillis: Long,
    private val maxKeys: Int = 64,
) {
    private data class State(
        var windowStartedAt: Long,
        var lastAttemptAt: Long,
        var attempts: Int,
    )

    private val lock = Any()
    private val states = LinkedHashMap<String, State>()

    init {
        require(maxAttemptsPerWindow in 1..32)
        require(windowMillis in 1_000L..86_400_000L)
        require(cooldownMillis in 0L..windowMillis)
        require(maxKeys in 1..1024)
    }

    fun tryAcquire(key: String, nowMillis: Long): RecoveryBudgetDecision = synchronized(lock) {
        require(key.length in 1..96 && key.none(Char::isWhitespace))
        val now = nowMillis.coerceAtLeast(0L)
        val current = states[key]
        val state = if (current == null || now < current.windowStartedAt || now - current.windowStartedAt >= windowMillis) {
            State(windowStartedAt = now, lastAttemptAt = Long.MIN_VALUE, attempts = 0).also {
                if (states.size >= maxKeys) states.entries.iterator().let { iterator -> if (iterator.hasNext()) { iterator.next(); iterator.remove() } }
                states[key] = it
            }
        } else current

        val sinceLast = if (state.lastAttemptAt == Long.MIN_VALUE) Long.MAX_VALUE else (now - state.lastAttemptAt).coerceAtLeast(0L)
        if (state.attempts >= maxAttemptsPerWindow) {
            val retryAt = state.windowStartedAt + windowMillis
            return@synchronized RecoveryBudgetDecision(false, state.attempts, (retryAt - now).coerceAtLeast(0L))
        }
        if (sinceLast < cooldownMillis) {
            return@synchronized RecoveryBudgetDecision(false, state.attempts, (cooldownMillis - sinceLast).coerceAtLeast(0L))
        }
        state.attempts++
        state.lastAttemptAt = now
        RecoveryBudgetDecision(true, state.attempts, 0L)
    }

    fun clear(key: String) = synchronized(lock) { states.remove(key); Unit }

    fun clearAll() = synchronized(lock) { states.clear() }
}
