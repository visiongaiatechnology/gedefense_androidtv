package de.visiongaia.gedefense.tv.core.titan.response

/**
 * One allow-listed command that the Titan response engine may execute through the confirmed
 * privileged shell channel.
 *
 * Only [TitanCommandFactory] creates instances. Every argument is validated against a strict
 * character class, so the command can be joined into a single `su -c` line without enabling shell
 * injection even if it were ever executed through a shell. There is no generic "exec" API by design.
 */
data class TitanShellCommand(
    val program: String,
    val arguments: List<String>,
    val requiresRoot: Boolean,
    val auditTag: String,
    val allowsShizuku: Boolean = false,
) {
    init {
        require(program in ALLOWED_PROGRAMS) { "command program not allowed: $program" }
        require(arguments.size <= MAX_ARGUMENTS) { "too many command arguments" }
        require(arguments.all { it.length in 1..MAX_ARGUMENT_LENGTH && SAFE_ARGUMENT.matches(it) }) {
            "unsafe command argument"
        }
        require(auditTag.matches(AUDIT_TAG)) { "invalid command audit tag" }
    }

    /** Stable, secret-free representation for logs and evidence (tag plus program only). */
    fun auditLine(): String = "$auditTag:${program}(${arguments.size})"

    /** Shell line for the privileged channel; safe because every argument is charset-validated. */
    fun shellLine(): String = (listOf(program) + arguments).joinToString(" ")

    companion object {
        const val MAX_ARGUMENTS = 16
        const val MAX_ARGUMENT_LENGTH = 512
        private val SAFE_ARGUMENT = Regex("[A-Za-z0-9_./:@+=,%-]+")
        private val AUDIT_TAG = Regex("[a-z][a-z0-9-]{2,63}")

        /** Programs the response engine may ever invoke; deliberately minimal. */
        val ALLOWED_PROGRAMS: Set<String> = setOf(
            "pm",
            "am",
            "iptables",
            "setprop",
            "stop",
            "kill",
            "chmod",
            "mv",
            "mkdir",
            "cmd",
            "getprop",
            "id",
            // Read-only introspection programs used by the socket/FIM collectors over the confirmed
            // root channel. They can only read; the allowlist never contains a destructive tool.
            "find",
            "stat",
            "sha256sum",
            "cat",
            "ls",
        )
    }
}
