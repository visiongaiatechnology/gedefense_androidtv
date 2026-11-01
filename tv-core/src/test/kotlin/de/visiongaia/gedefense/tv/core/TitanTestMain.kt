package de.visiongaia.gedefense.tv.core

import kotlin.system.exitProcess

// --- tiny assertion harness (mirrors KineticTestMain) ------------------------------------------

internal var titanPassedChecks = 0
internal var titanFailedChecks = 0
internal val titanTests = mutableListOf<Pair<String, () -> Unit>>()

internal fun titanTest(name: String, body: () -> Unit) { titanTests += name to body }

internal fun titanCheck(condition: Boolean, message: String) {
    if (condition) titanPassedChecks += 1 else { titanFailedChecks += 1; throw AssertionError(message) }
}

internal fun titanCheckTrue(condition: Boolean, message: String) = titanCheck(condition, message)

internal fun titanCheckEquals(actual: Any?, expected: Any?, message: String) =
    titanCheck(actual == expected, "$message (expected=$expected actual=$actual)")

internal inline fun <reified T : Throwable> titanCheckThrows(message: String, block: () -> Unit) {
    try {
        block()
    } catch (throwable: Throwable) {
        if (throwable is T) { titanCheck(true, message); return }
        titanCheck(false, "$message (wrong exception: ${throwable::class.simpleName}: ${throwable.message})")
        return
    }
    titanCheck(false, "$message (no exception thrown)")
}

fun main() {
    registerTitanTests()
    var failedTestCases = 0
    titanTests.forEach { (name, body) ->
        val failuresBefore = titanFailedChecks
        try {
            body()
            if (titanFailedChecks == failuresBefore) println("ok   $name") else { failedTestCases += 1; println("FAIL $name") }
        } catch (throwable: Throwable) {
            if (titanFailedChecks == failuresBefore) titanFailedChecks += 1
            failedTestCases += 1
            println("FAIL $name -> ${throwable::class.simpleName}: ${throwable.message}")
            throwable.stackTrace.take(8).forEach { frame -> println("       at $frame") }
        }
    }
    println()
    println("PASS $titanPassedChecks / FAIL $titanFailedChecks")
    println("TESTS: ${titanTests.size - failedTestCases} passed, $failedTestCases failed")
    if (titanFailedChecks > 0 || failedTestCases > 0) exitProcess(1)
}

private fun registerTitanTests() {
    registerProcSocketTests()
    registerFimWitnessTests()
    registerCommandPolicyTests()
    registerMatrixEventTests()
}
