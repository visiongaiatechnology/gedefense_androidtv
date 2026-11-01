package de.visiongaia.gedefense.tv.data

import android.content.SharedPreferences
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus

/**
 * Persistence of the local witness-protocol state and its anti-rollback sequence counter.
 *
 * The sequence is allocated with a synchronous commit before a checkpoint is issued, so a crash
 * between allocation and checkpoint storage can never reuse a sequence number. `checkpointsCreated`
 * is used as a lower bound for the next allocation as well, which keeps the counter monotonic even
 * if the sequence key was lost.
 *
 * The witness state is local-only: the alpha never claims a paired counterpart, and a corrupt block
 * degrades to [TitanWitnessStatus.UNAVAILABLE] instead of inventing checkpoints.
 */
internal class TitanWitnessCodec(private val prefs: TitanPrefs) {

    fun load(): TitanWitnessStatus = try {
        loadInternal()
    } catch (_: Throwable) {
        TitanWitnessStatus.UNAVAILABLE
    }

    private fun loadInternal(): TitanWitnessStatus {
        if (prefs.readInt(KEY_VERSION) != TitanPrefs.FORMAT_VERSION) return TitanWitnessStatus.UNAVAILABLE
        val state = parseState(prefs.readString(KEY_STATE)) ?: return TitanWitnessStatus.UNAVAILABLE
        val checkpoints = prefs.readLong(KEY_CHECKPOINTS)?.coerceIn(0L, MAX_SEQUENCE) ?: 0L
        val lastAt = prefs.readLong(KEY_LAST_AT)?.takeIf { it > 0L }
        val prefix = prefs.readString(KEY_PREFIX)?.takeIf { DIGEST_PREFIX_PATTERN.matches(it) }
        return try {
            TitanWitnessStatus(
                state = state,
                checkpointsCreated = checkpoints,
                lastCheckpointAtMillis = lastAt,
                lastLedgerDigestPrefix = prefix,
                note = TitanNoteCodec.decodeSingle(prefs.readString(KEY_NOTE)),
            )
        } catch (_: IllegalArgumentException) {
            TitanWitnessStatus.UNAVAILABLE
        }
    }

    fun save(status: TitanWitnessStatus) {
        try {
            val editor = prefs.editor()
            write(editor, status)
            prefs.commit(editor)
        } catch (_: Throwable) {
            // Fail-soft: the controller keeps the in-memory checkpoint status.
        }
    }

    /** Writes the witness block into an existing editor (used by the combined status save). */
    fun write(editor: SharedPreferences.Editor, status: TitanWitnessStatus) {
        editor.putInt(KEY_VERSION, TitanPrefs.FORMAT_VERSION)
        editor.putString(KEY_STATE, status.state.name)
        editor.putLong(KEY_CHECKPOINTS, status.checkpointsCreated.coerceIn(0L, MAX_SEQUENCE))
        val lastAt = status.lastCheckpointAtMillis
        if (lastAt != null && lastAt > 0L) {
            editor.putLong(KEY_LAST_AT, lastAt)
        } else {
            editor.remove(KEY_LAST_AT)
        }
        val prefix = status.lastLedgerDigestPrefix
        if (prefix != null && DIGEST_PREFIX_PATTERN.matches(prefix)) {
            editor.putString(KEY_PREFIX, prefix)
        } else {
            editor.remove(KEY_PREFIX)
        }
        val note = TitanNoteCodec.encodeSingle(status.note)
        if (note == null) editor.remove(KEY_NOTE) else editor.putString(KEY_NOTE, note)
    }

    /** Highest allocated sequence (0 when none was allocated on this device). */
    fun sequence(): Long = try {
        prefs.readLong(KEY_SEQUENCE)?.coerceIn(0L, MAX_SEQUENCE) ?: 0L
    } catch (_: Throwable) {
        0L
    }

    /**
     * Atomically reserves the next sequence and persists it before returning. Returns 0 when the
     * counter is exhausted or the write failed - callers must then report the witness as unavailable
     * instead of issuing a checkpoint with a guessing number.
     */
    fun allocate(): Long = try {
        val stored = prefs.readLong(KEY_SEQUENCE)?.coerceIn(0L, MAX_SEQUENCE) ?: 0L
        val checkpoints = loadInternal().checkpointsCreated.coerceIn(0L, MAX_SEQUENCE)
        val next = maxOf(stored, checkpoints) + 1L
        if (next <= 0L || next > MAX_SEQUENCE) {
            0L
        } else {
            val persisted = prefs.commit(prefs.editor().putLong(KEY_SEQUENCE, next))
            if (persisted) next else 0L
        }
    } catch (_: Throwable) {
        0L
    }

    private fun parseState(name: String?): TitanWitnessState? = try {
        name?.let { TitanWitnessState.valueOf(it) }
    } catch (_: IllegalArgumentException) {
        null
    }

    private companion object {
        /** Sequence high-water mark; far above any realistic checkpoint count but far below Long.MAX. */
        const val MAX_SEQUENCE = 9_000_000_000_000_000L
        val DIGEST_PREFIX_PATTERN = Regex("[0-9a-f]{8,16}")

        const val KEY_VERSION = "witness.version"
        const val KEY_STATE = "witness.state"
        const val KEY_CHECKPOINTS = "witness.checkpoints"
        const val KEY_LAST_AT = "witness.last_at"
        const val KEY_PREFIX = "witness.prefix"
        const val KEY_NOTE = "witness.note"
        const val KEY_SEQUENCE = "witness.sequence"
    }
}
