package de.visiongaia.gedefense.tv.core.event

import de.visiongaia.gedefense.tv.core.model.TvEvent

/**
 * Serialises the XDR-lite event schema to one JSON object per line (JSONL).
 *
 * Guarantees:
 *  - output is deterministic for the same event;
 *  - strings are fully escaped (no raw newlines/control characters);
 *  - decode() rejects malformed or unknown-required-field input instead of guessing;
 *  - the wire format stays stable so that exported evidence can be verified offline.
 */
interface EventCodec {
    fun encode(event: TvEvent): String

    fun encodeAll(events: List<TvEvent>): String =
        if (events.isEmpty()) "" else events.joinToString(separator = "\n", postfix = "\n") { encode(it) }

    /** Returns null when the line is not a valid event; never fabricates defaults. */
    fun decode(line: String): TvEvent?
}
