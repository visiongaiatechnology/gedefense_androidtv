package de.visiongaia.gedefense.mobile.core

import java.io.File
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private fun assertTrue(v:Boolean,msg:String){if(!v) throw AssertionError(msg)}
private fun assertEq(a:Any?,b:Any?,msg:String){if(a!=b) throw AssertionError("$msg: expected=$b actual=$a")}


private fun testFullPolicyFingerprintDeterminism() {
    val a = listOf(
        ThreatRecord("cins", IpPrefix.parse("203.0.113.8/32")!!),
        ThreatRecord("feodo", IpPrefix.parse("198.51.100.7/32")!!),
        ThreatRecord("tor-exits", IpPrefix.parse("2001:db8:abcd::1/128")!!),
    )
    val b = a.reversed()
    val ia = ThreatIndex.build(a)
    val ib = ThreatIndex.build(b)
    check(ia.fullPolicySha256 == ib.fullPolicySha256)
    check(ia.fullPolicySha256.matches(Regex("[0-9a-f]{64}")))
    val changed = ThreatIndex.build(a + ThreatRecord("ipsum", IpPrefix.parse("203.0.113.9/32")!!))
    check(changed.fullPolicySha256 != ia.fullPolicySha256)
}


private fun testNetworkRangePlanner() {
    val home = NetworkRangePlanner.plan(byteArrayOf(192.toByte(), 168.toByte(), 50, 7), 24)!!
    assertEq(home.targets.size, 253, "private /24 excludes local host")
    assertTrue("192.168.50.7" !in home.targets, "local address excluded")
    assertTrue(!home.scopeClamped, "normal /24 is not clamped")

    val broad = NetworkRangePlanner.plan(byteArrayOf(10, 44, 9, 20), 16)!!
    assertEq(broad.effectivePrefixLength, 24, "broad LAN clamps to /24")
    assertTrue(broad.scopeClamped, "broad LAN reports clamp")
    assertTrue(broad.targets.all { it.startsWith("10.44.9.") }, "clamped scan never escapes local /24")

    val public = NetworkRangePlanner.plan(byteArrayOf(8, 8, 8, 8), 24)
    assertTrue(public == null, "public IPv4 range refused")
    val pointToPoint = NetworkRangePlanner.plan(byteArrayOf(192.toByte(), 168.toByte(), 1, 10), 32)!!
    assertTrue(pointToPoint.targets.isEmpty(), "/32 produces no active sweep")
}


private fun testMdnsDnsCodec() {
    val query = MdnsDnsCodec.buildPtrQuery(listOf("_http._tcp.local", "_adb-tls-connect._tcp.local"))!!
    assertTrue(query.size in 20..1400, "mDNS query bounded")
    assertEq(((query[4].toInt() and 0xff) shl 8) or (query[5].toInt() and 0xff), 2, "mDNS question count")

    fun putU16(out: java.io.ByteArrayOutputStream, value: Int) { out.write((value ushr 8) and 0xff); out.write(value and 0xff) }
    fun putU32(out: java.io.ByteArrayOutputStream, value: Long) {
        out.write(((value ushr 24) and 0xff).toInt()); out.write(((value ushr 16) and 0xff).toInt())
        out.write(((value ushr 8) and 0xff).toInt()); out.write((value and 0xff).toInt())
    }
    fun putName(out: java.io.ByteArrayOutputStream, name: String) {
        name.split('.').forEach { label -> val b=label.toByteArray(); out.write(b.size); out.write(b) }; out.write(0)
    }

    val out = java.io.ByteArrayOutputStream()
    repeat(2) { putU16(out, 0) }; putU16(out, 0); putU16(out, 4); putU16(out, 0); putU16(out, 0)
    // PTR _http._tcp.local -> Living Room._http._tcp.local
    putName(out, "_http._tcp.local"); putU16(out, 12); putU16(out, 1); putU32(out, 120);
    val ptr = java.io.ByteArrayOutputStream().also { putName(it, "Living Room._http._tcp.local") }.toByteArray(); putU16(out, ptr.size); out.write(ptr)
    // SRV instance -> speaker.local:8080
    putName(out, "Living Room._http._tcp.local"); putU16(out, 33); putU16(out, 1); putU32(out, 120)
    val srv = java.io.ByteArrayOutputStream().also { putU16(it,0); putU16(it,0); putU16(it,8080); putName(it,"speaker.local") }.toByteArray(); putU16(out,srv.size); out.write(srv)
    // A speaker.local -> 192.168.1.44
    putName(out, "speaker.local"); putU16(out, 1); putU16(out, 1); putU32(out, 120); putU16(out,4); out.write(byteArrayOf(192.toByte(),168.toByte(),1,44))
    // TXT instance
    putName(out, "Living Room._http._tcp.local"); putU16(out, 16); putU16(out, 1); putU32(out, 120)
    val txt = "model=VGT".toByteArray(); putU16(out, txt.size+1); out.write(txt.size); out.write(txt)

    val parsed = MdnsDnsCodec.parse(out.toByteArray())!!
    assertEq(parsed.records.size, 4, "mDNS supported record parsing")
    assertTrue(parsed.records.any { it.type == MdnsDnsCodec.TYPE_A && it.textValue == "192.168.1.44" }, "mDNS A record")
    assertTrue(parsed.records.any { it.type == MdnsDnsCodec.TYPE_SRV && it.port == 8080 && it.textValue == "speaker.local" }, "mDNS SRV record")
    assertTrue(parsed.records.any { it.type == MdnsDnsCodec.TYPE_PTR && it.textValue == "living room._http._tcp.local" }, "mDNS PTR record")

    val loop = ByteArray(18)
    loop[6]=0; loop[7]=1 // one answer
    loop[12]=0xc0.toByte(); loop[13]=12 // owner name points to itself
    assertTrue(MdnsDnsCodec.parse(loop) == null, "mDNS compression loop rejected")
    assertTrue(MdnsDnsCodec.buildPtrQuery(listOf("bad\u0000.local")) == null, "mDNS control characters refused")
}


private fun testLanBehaviorEvaluator() {
    val learning = LanBehaviorEvaluator.deviceSignals(LanDeviceBehaviorInput(
        observations = 3, historicalRiskScore = 10, currentRiskScore = 90,
        newlyExposedPorts = 5, newlyAdvertisedServices = 5,
        lastSeenMillis = 0L, nowMillis = 20L * 24L * 60L * 60L * 1000L,
    ))
    assertTrue(learning.isEmpty(), "LAN behavior must not alert before learning maturity")

    val device = LanBehaviorEvaluator.deviceSignals(LanDeviceBehaviorInput(
        observations = 6, historicalRiskScore = 12, currentRiskScore = 72,
        newlyExposedPorts = 2, newlyAdvertisedServices = 2,
        lastSeenMillis = 0L, nowMillis = 8L * 24L * 60L * 60L * 1000L,
    ))
    assertTrue("service_burst" in device, "LAN service burst detected")
    assertTrue("exposure_risk_spike" in device, "LAN exposure-risk spike detected")
    assertTrue("return_with_surface_drift" in device, "LAN return-with-drift detected")

    val network = LanBehaviorEvaluator.networkSignals(LanNetworkBehaviorInput(
        observations = 8, historicalDeviceCount = 4, currentDeviceCount = 10,
        historicalElevatedCount = 1, currentElevatedCount = 4,
    ))
    assertTrue("device_surge" in network, "LAN device surge detected")
    assertTrue("risk_surge" in network, "LAN elevated-device surge detected")

    val stable = LanBehaviorEvaluator.networkSignals(LanNetworkBehaviorInput(
        observations = 8, historicalDeviceCount = 8, currentDeviceCount = 9,
        historicalElevatedCount = 2, currentElevatedCount = 2,
    ))
    assertTrue(stable.isEmpty(), "normal LAN variation must remain quiet")
}


private fun testPortSentinelClassifier() {
    val adb = PortSentinelClassifier.assess(5555, 1)
    assertEq(adb.code, "LAN_ADB_PROBE_DETECTED", "ADB probe classification")
    assertEq(adb.risk, SentinelRisk.CRITICAL, "ADB probe risk")

    val scan = PortSentinelClassifier.assess(8080, 3)
    assertEq(scan.code, "LAN_PORT_SCAN_DETECTED", "multi-port scan classification")
    assertEq(scan.risk, SentinelRisk.HIGH, "three-port scan risk")

    val broad = PortSentinelClassifier.assess(1080, 6)
    assertEq(broad.risk, SentinelRisk.CRITICAL, "broad port scan escalates")

    var refused = false
    try { PortSentinelClassifier.assess(22, 1) } catch (_: IllegalArgumentException) { refused = true }
    assertTrue(refused, "unmonitored destination port refused")
}

private fun testDurableAtomicFiles() {
    val dir = java.nio.file.Files.createTempDirectory("gedefense-durable-atomic").toFile()
    try {
        val target = java.io.File(dir, "state.bin")
        target.writeBytes("old".toByteArray())
        val temp = java.io.File(dir, ".state.new")
        java.io.FileOutputStream(temp).use { output ->
            output.write("new-state".toByteArray())
            output.fd.sync()
        }
        DurableAtomicFiles.replace(temp, target)
        assertEq(target.readText(), "new-state", "durable atomic replacement publishes candidate")
        assertTrue(!temp.exists(), "durable atomic replacement consumes candidate")

        val outside = java.nio.file.Files.createTempDirectory("gedefense-durable-outside").toFile()
        try {
            val escaped = java.io.File(outside, "candidate")
            escaped.writeText("escape")
            var refused = false
            try {
                DurableAtomicFiles.replace(escaped, target)
            } catch (_: java.io.IOException) {
                refused = true
            }
            assertTrue(refused, "durable atomic replacement refuses cross-directory candidate")
            assertEq(target.readText(), "new-state", "refused durable replace preserves authoritative target")
        } finally {
            outside.deleteRecursively()
        }
    } finally {
        dir.deleteRecursively()
    }
}

private fun testAuthenticatedSnapshotStore() {
    val dir = java.nio.file.Files.createTempDirectory("gedefense-auth-store").toFile()
    try {
        val file = java.io.File(dir, "state.bin")
        val key = javax.crypto.spec.SecretKeySpec(ByteArray(32) { i -> (i * 7 + 3).toByte() }, "HmacSHA256")
        val store = AuthenticatedSnapshotStore(file, key, schemaVersion = 7, maxPayloadBytes = 4096)
        check(store.read().state == AuthenticatedSnapshotState.ABSENT)
        val payload = "security-state-v1".toByteArray()
        store.write(payload)
        val valid = store.read()
        check(valid.state == AuthenticatedSnapshotState.VALID)
        check(valid.payload!!.contentEquals(payload))

        val bytes = file.readBytes()
        bytes[bytes.size / 2] = (bytes[bytes.size / 2].toInt() xor 0x01).toByte()
        file.writeBytes(bytes)
        val tampered = store.read()
        check(tampered.state == AuthenticatedSnapshotState.INVALID) { "snapshot tamper must fail authentication" }
        assertEq(tampered.failureKind, AuthenticatedSnapshotFailureKind.AUTHENTICATION_FAILED, "snapshot tamper classification")

        store.write(payload)
        file.writeBytes(file.readBytes().copyOf(file.length().toInt() - 1))
        val truncated = store.read()
        check(truncated.state == AuthenticatedSnapshotState.INVALID) { "snapshot truncation must fail authentication" }
        assertEq(truncated.failureKind, AuthenticatedSnapshotFailureKind.FORMAT_INVALID, "snapshot truncation classification")

        store.write(payload)
        val unusableKey = object : javax.crypto.SecretKey {
            override fun getAlgorithm(): String = "HmacSHA256"
            override fun getFormat(): String = "RAW"
            override fun getEncoded(): ByteArray? = null
        }
        val keyFailure = AuthenticatedSnapshotStore(file, unusableKey, schemaVersion = 7, maxPayloadBytes = 4096).read()
        assertEq(keyFailure.state, AuthenticatedSnapshotState.INVALID, "provider key failure fails closed")
        assertEq(keyFailure.reason, "snapshot key operation failed", "provider key failure reason bounded")
        assertEq(keyFailure.failureKind, AuthenticatedSnapshotFailureKind.KEY_OPERATION, "provider key failure classification")

        // Recovery parser may expose only structurally valid framing. The returned payload is
        // explicitly unauthenticated and is safe only when a caller independently authenticates an
        // inner AEAD envelope before use. Tampering the outer MAC must not prevent that extraction.
        store.write(payload)
        val macTampered = file.readBytes()
        macTampered[macTampered.lastIndex] = (macTampered.last().toInt() xor 0x01).toByte()
        file.writeBytes(macTampered)
        val recoveryPayload = store.readPayloadWithoutAuthenticationForAeadRecovery()
        assertTrue(recoveryPayload != null && recoveryPayload.contentEquals(payload), "AEAD recovery parser extracts bounded payload despite outer MAC failure")
        recoveryPayload?.fill(0)

        file.writeBytes(macTampered.copyOf(macTampered.size - 1))
        assertTrue(store.readPayloadWithoutAuthenticationForAeadRecovery() == null, "AEAD recovery parser rejects truncated framing")

        var oversizeRejected = false
        try { store.write(ByteArray(4097)) } catch (_: IllegalArgumentException) { oversizeRejected = true }
        check(oversizeRejected) { "snapshot oversized write must be rejected" }
    } finally {
        dir.deleteRecursively()
    }
}

private fun testUnavailableAuthenticatedPersistence() {
    val dir = java.nio.file.Files.createTempDirectory("gedefense-unavailable-auth").toFile()
    try {
        val file = java.io.File(dir, "state.bin")
        val store = AuthenticatedSnapshotStore(file, null, schemaVersion = 1, maxPayloadBytes = 64)
        val read = store.read()
        assertEq(read.state, AuthenticatedSnapshotState.INVALID, "missing persistence key fails closed")
        assertEq(read.reason, "snapshot key unavailable", "missing persistence key reason bounded")
        assertEq(read.failureKind, AuthenticatedSnapshotFailureKind.KEY_UNAVAILABLE, "missing persistence key classification")
        var writeRejected = false
        try {
            store.write(byteArrayOf(1, 2, 3))
        } catch (_: java.io.IOException) {
            writeRejected = true
        }
        assertTrue(writeRejected, "missing persistence key rejects writes")
        assertTrue(!file.exists(), "missing persistence key cannot create unauthenticated state")
        assertTrue(!store.clear(), "missing persistence key cannot clear continuity state")

        val threatStore = ThreatCacheStore(java.io.File(dir, "feeds"), null)
        assertEq(threatStore.loadSnapshot().count, 0, "missing threat key publishes no policy")
        val baseline = IntegrityBaselineStore(java.io.File(dir, "integrity.v1"), null)
        val decision = baseline.verifyOrAdvance(
            IntegrityIdentity("de.visiongaia.gedefense.mobile", 1, "1".repeat(64), "2".repeat(64)),
        )
        assertTrue(!decision.ok && decision.reason == "integrity_key_unavailable", "missing integrity key rejects trust")
    } finally {
        dir.deleteRecursively()
    }
}

private fun testManagedCaCertificateValidator() {
    val ca = java.util.Base64.getDecoder().decode("MIIDeDCCAmCgAwIBAgIUOHHUifUQ0r6y8NYYADZQ2oYsPBUwDQYJKoZIhvcNAQELBQAwQjEcMBoGA1UEAwwTR2VEZWZlbnNlIFRlc3QgUm9vdDEiMCAGA1UECgwZVmlzaW9uR2FpYVRlY2hub2xvZ3kgVGVzdDAeFw0yNjA5MTkyMzEyNTFaFw0zNjA5MTYyMzEyNTFaMEIxHDAaBgNVBAMME0dlRGVmZW5zZSBUZXN0IFJvb3QxIjAgBgNVBAoMGVZpc2lvbkdhaWFUZWNobm9sb2d5IFRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCya9bhE4E2u81tm49f8A8TImBV/7u7/RQqhxkpJC1uvRYX1FMSn0zuQNp/EUMyr1xahoNQy+y/U/JA3oCHAdmT7Nmo5XWBx9SP84sBdAuQapl96NGEJPuSwa4Q/vvJqCKm+zeQlgtiT5bCsCbeUvU/zy2lMm2V01DQM3tQyg2+FTZxGDSUFn6S1oVj/QlSKDgP5MFdmfA8tCx57TvWlScFckxNA2KwOyVRfs0Guz45hT0CQN/Wjy4uRyj7ieEsvDQI5R+tXNWcTm+ydOolpXZon886x6vBCqI1Ow47RaWC1l0Edsna9DhcWZNVfbIlteqBsi+1HIb2JaiX5wGlCWHTAgMBAAGjZjBkMB0GA1UdDgQWBBT982oxjW4lFvF+cDgX/8rV7zxm2zAfBgNVHSMEGDAWgBT982oxjW4lFvF+cDgX/8rV7zxm2zASBgNVHRMBAf8ECDAGAQH/AgEBMA4GA1UdDwEB/wQEAwIBBjANBgkqhkiG9w0BAQsFAAOCAQEAUFQBSVbwrja/7fAWLF5DJwJvlgPY605M5d+trtc+ar0CiZ5Z83FEpDo/mb1JvEW73gDY7CkymtCsQ428KTmyQw8vhv5QaWqf6k5LZCeVtTWIEpKOQrBoAeSLGy1BthUWcmU2FaTkVlAf+SdXAe09dn3zx9XNJEHHokRMhDiONtQHs0/7yMWIfwPPhn8lFHXmtew1tTCkqbpIf/5M+fWdQT/+ioLFYdXF3tWDGMPk+kwxAOCvKwSxuTVoVDUEm6lQ3B2m/bbtOby3K8KA/6ekP57UArOiBnZGXzRbUveAr9gbU58Z+8Y+WPkyRQkh2XlHTGEh8019ZrY6aK2pLcGR9g==")
    val leaf = java.util.Base64.getDecoder().decode("MIIDaDCCAlCgAwIBAgIUCw+IDvH5ohWw2Kr8ADUA+WVbO9swDQYJKoZIhvcNAQELBQAwQjEcMBoGA1UEAwwTR2VEZWZlbnNlIFRlc3QgUm9vdDEiMCAGA1UECgwZVmlzaW9uR2FpYVRlY2hub2xvZ3kgVGVzdDAeFw0yNjA5MTkyMzEyNTFaFw0zNjA5MTYyMzEyNTFaMDgxEjAQBgNVBAMMCWxlYWYudGVzdDEiMCAGA1UECgwZVmlzaW9uR2FpYVRlY2hub2xvZ3kgVGVzdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAK3AqDfwlhwM6zNFsh/rHv9edRQszGNiE1xoVWMPIeDuqRwb1x1CqZ7VzUar7s+WL2SgUi/X6Kx67EJiFmJY7mfjT8j/VPKVspjLWCgleCd9Jo9bGsHNCCHoiPtc7FTtoruTwjnc1T+mdNbVvv72RYAJtTEF6L8HGZoWnSMxQVCDUMqf14AxrQ6QORGWR4LVgbIcfwqbw10Va6+5XD1nO/E/c7oRFfIBHh+1AQGMUu1heLRUB1bw66lzX5EpCd4Cqyb0nAeIciVuftorPMI9PauM99/PMBKarhQjR7ZKmSNj4guG4sYMlHPPWUoEvpsJ7+2q0CG4l+WCs5qWTpZQyVsCAwEAAaNgMF4wDAYDVR0TAQH/BAIwADAOBgNVHQ8BAf8EBAMCBaAwHQYDVR0OBBYEFKkpSQeQzkmHy9B7Q8uO0zOrLsEoMB8GA1UdIwQYMBaAFP3zajGNbiUW8X5wOBf/ytXvPGbbMA0GCSqGSIb3DQEBCwUAA4IBAQArMTZhf7rMOjdRkAC8iai9vdFEPSKxQeUlFgBiDMFbZUc+7rMa92YgV0Mj4cKDTxHzUX1LSJBLJh1YxlIAAistv/Zdzhc1zZE8b1iltbY8v3b1nkz7CXIKEDLti6jusrY4KdLz0KvzkZ9xlBhV0mRqwKqJgGfte28A1ncwghF54FJ5N7utWJ3Vq/aCOJH0ikIKc2ZFnUyx6mhi8hRA6yvmxZ65lNPHZS4e0plnqOrkqdnJ/1Aeu2MRFMCqksyvCs2HvHJcBayjWoBEe6EQOsamOPayIQ/3loO2AwQumdLFAtRA82GQIb2nSRFEZpzJm+eDEQ41vmplAhMYf5Jck4IY")
    val valid = ManagedCaCertificateValidator.inspect(ca)
    assertTrue(valid != null, "valid X.509 CA accepted")
    assertTrue(valid!!.subject.contains("GeDefense Test Root"), "CA subject retained")
    assertTrue(valid.sha256Fingerprint.matches(Regex("(?:[0-9A-F]{2}:){31}[0-9A-F]{2}")), "CA fingerprint canonical")
    assertTrue(ManagedCaCertificateValidator.inspect(leaf) == null, "leaf certificate rejected as trust anchor")
    assertTrue(ManagedCaCertificateValidator.inspect(ca + ca) == null, "multiple certificates rejected")
    assertTrue(ManagedCaCertificateValidator.inspect(ByteArray(ManagedCaCertificateValidator.MAX_BYTES + 1)) == null, "oversized CA input rejected")
}

private fun testUnavailableEvidenceStore() {
    val store: EvidenceStore = UnavailableEvidenceStore("evidence_crypto_failure")
    assertEq(store.open(), LedgerHealth(false, 0L, "evidence_crypto_failure"), "unavailable evidence open fails closed")
    assertEq(store.verify(), LedgerHealth(false, 0L, "evidence_crypto_failure"), "unavailable evidence verify fails closed")
    assertTrue(!store.verifyRecoveryArchive(File("missing.manifest")).ok, "unavailable evidence recovery verification refused")
    var appendRejected = false
    try {
        store.append(EvidenceEvent("TEST", "INFO", "local", "failure path"))
    } catch (error: EvidenceStoreUnavailableException) {
        assertEq(error.reasonCode, "evidence_crypto_failure", "unavailable evidence preserves typed failure")
        appendRejected = true
    }
    assertTrue(appendRejected, "unavailable evidence append rejected")
    var invalidReasonRejected = false
    try {
        UnavailableEvidenceStore("../../invalid")
    } catch (_: IllegalArgumentException) {
        invalidReasonRejected = true
    }
    assertTrue(invalidReasonRejected, "unavailable evidence reason constrained")
}

private fun testBoundedOpaqueCryptoIsolation() {
    val opaque = object : javax.crypto.SecretKey {
        override fun getAlgorithm(): String = "HmacSHA256"
        override fun getFormat(): String? = null
        override fun getEncoded(): ByteArray? = null
    }
    val started = System.nanoTime()
    var timedOut = false
    try {
        BoundedSecretKeyCrypto.execute(opaque, timeoutMillis = 50L) {
            Thread.sleep(5_000L)
            byteArrayOf(1)
        }
    } catch (_: java.security.GeneralSecurityException) {
        timedOut = true
    }
    val elapsedMs = (System.nanoTime() - started) / 1_000_000L
    assertTrue(timedOut, "opaque crypto timeout fails closed")
    assertTrue(elapsedMs < 1_000L, "opaque crypto timeout is bounded")

    val retryStarted = System.nanoTime()
    var circuitRejected = false
    try {
        BoundedSecretKeyCrypto.execute(opaque, timeoutMillis = 50L) { byteArrayOf(2) }
    } catch (_: java.security.GeneralSecurityException) {
        circuitRejected = true
    }
    val retryElapsedMs = (System.nanoTime() - retryStarted) / 1_000_000L
    assertTrue(circuitRejected, "opaque crypto circuit stays fail-closed after provider hang")
    assertTrue(retryElapsedMs < 250L, "opaque crypto circuit fails fast")
}


private fun testPrivacyIntelligenceRegistry() {
    val prov = PrivacyProvenance(
        sourceId = "test-source",
        sourceUrl = "https://example.test/source",
        licenseId = "TEST-1.0",
        observedAt = "2026-09-22",
    )
    val registry = PrivacyIntelligenceRegistry.build(
        listOf(
            PrivacyRule(
                id = "tracker-example",
                domain = "metrics.example.test",
                includeSubdomains = true,
                category = PrivacyCategory.ANALYTICS,
                confidence = PrivacyConfidence.HIGH,
                breakageRisk = PrivacyBreakageRisk.LOW,
                essential = false,
                provenance = prov,
            ),
            PrivacyRule(
                id = "essential-subdomain",
                domain = "critical.metrics.example.test",
                includeSubdomains = true,
                category = PrivacyCategory.ESSENTIAL_CONNECTIVITY,
                confidence = PrivacyConfidence.HIGH,
                breakageRisk = PrivacyBreakageRisk.LOW,
                essential = true,
                provenance = prov,
            ),
            PrivacyRule(
                id = "diagnostics-medium",
                domain = "diag.example.test",
                includeSubdomains = false,
                category = PrivacyCategory.DIAGNOSTICS,
                confidence = PrivacyConfidence.HIGH,
                breakageRisk = PrivacyBreakageRisk.MEDIUM,
                essential = false,
                provenance = prov,
            ),
            PrivacyRule(
                id = "encrypted-dns-test",
                domain = "resolver.example.test",
                includeSubdomains = true,
                category = PrivacyCategory.ENCRYPTED_DNS,
                confidence = PrivacyConfidence.HIGH,
                breakageRisk = PrivacyBreakageRisk.MEDIUM,
                essential = false,
                provenance = prov,
            ),
        ),
    )
    assertEq(registry.count, 4, "privacy registry count")
    assertTrue(registry.fingerprintSha256.matches(Regex("[0-9a-f]{64}")), "privacy registry fingerprint")
    assertEq(registry.decide("metrics.example.test", PrivacyProfile.CONSERVATIVE).action, PrivacyAction.BLOCK, "conservative high-confidence analytics block")
    assertEq(registry.decide("sub.metrics.example.test", PrivacyProfile.BALANCED).action, PrivacyAction.BLOCK, "suffix rule applies to subdomain")
    assertEq(registry.decide("critical.metrics.example.test", PrivacyProfile.STRICT).action, PrivacyAction.ALLOW, "essential rule overrides tracker parent")
    assertEq(registry.decide("diag.example.test", PrivacyProfile.BALANCED).action, PrivacyAction.OBSERVE, "balanced avoids medium breakage diagnostic block")
    assertEq(registry.decide("diag.example.test", PrivacyProfile.STRICT).action, PrivacyAction.BLOCK, "strict blocks bounded diagnostic telemetry")
    assertEq(registry.decide("resolver.example.test", PrivacyProfile.BALANCED).action, PrivacyAction.OBSERVE, "balanced observes encrypted DNS bootstrap")
    assertEq(registry.decide("resolver.example.test", PrivacyProfile.STRICT).action, PrivacyAction.BLOCK, "strict blocks known encrypted DNS bootstrap")
    assertEq(registry.decide("evilmetrics.example.test", PrivacyProfile.STRICT).action, PrivacyAction.ALLOW, "suffix boundary cannot overmatch")
    assertTrue(canonicalPrivacyDomain("A.Example.TEST.") == "a.example.test", "privacy domain canonicalization")
    assertTrue(canonicalPrivacyDomain("../example.test") == null, "privacy domain rejects invalid labels")

    var cleartextProvenanceRejected = false
    try {
        PrivacyProvenance(
            sourceId = "cleartext-test",
            sourceUrl = "http" + "://example.test/source",
            licenseId = "TEST-1.0",
            observedAt = "2026-09-22",
        )
    } catch (_: IllegalArgumentException) { cleartextProvenanceRejected = true }
    assertTrue(cleartextProvenanceRejected, "privacy provenance rejects cleartext HTTP")

    var duplicateRejected = false
    try {
        PrivacyIntelligenceRegistry.build(listOf(
            PrivacyRule("duplicate-rule", "a.example.test", false, PrivacyCategory.ANALYTICS, PrivacyConfidence.HIGH, PrivacyBreakageRisk.LOW, false, prov),
            PrivacyRule("duplicate-rule", "b.example.test", false, PrivacyCategory.ANALYTICS, PrivacyConfidence.HIGH, PrivacyBreakageRisk.LOW, false, prov),
        ))
    } catch (_: IllegalArgumentException) { duplicateRejected = true }
    assertTrue(duplicateRejected, "duplicate privacy rule IDs rejected")
}


private fun testRecoveryAttemptBudget() {
    val budget = RecoveryAttemptBudget(maxAttemptsPerWindow = 3, windowMillis = 60_000L, cooldownMillis = 5_000L, maxKeys = 2)
    val first = budget.tryAcquire("integrity", 10_000L)
    assertTrue(first.allowed && first.attemptsInWindow == 1, "first recovery allowed")
    val cooldown = budget.tryAcquire("integrity", 12_000L)
    assertTrue(!cooldown.allowed && cooldown.retryAfterMillis == 3_000L, "recovery cooldown enforced")
    assertTrue(budget.tryAcquire("integrity", 15_000L).allowed, "second recovery after cooldown")
    assertTrue(budget.tryAcquire("integrity", 20_000L).allowed, "third recovery after cooldown")
    val exhausted = budget.tryAcquire("integrity", 25_000L)
    assertTrue(!exhausted.allowed && exhausted.attemptsInWindow == 3, "recovery attempt window bounded")
    val reset = budget.tryAcquire("integrity", 70_001L)
    assertTrue(reset.allowed && reset.attemptsInWindow == 1, "recovery window resets")
    budget.clear("integrity")
    assertTrue(budget.tryAcquire("integrity", 70_002L).allowed, "successful repair clears component budget")
    budget.tryAcquire("one", 1L)
    budget.tryAcquire("two", 1L)
    assertTrue(budget.tryAcquire("three", 1L).allowed, "bounded key map accepts replacement")
}


private fun testTelemetryLearningPolicy() {
    val first = TelemetryLearningPolicy.promote(0)
    assertEq(first.count, 1, "telemetry first session candidate")
    assertTrue(!first.confirmed, "telemetry first session not confirmed")
    val second = TelemetryLearningPolicy.promote(first.count)
    assertTrue(!second.confirmed, "telemetry second session remains pending")
    val third = TelemetryLearningPolicy.promote(second.count)
    assertTrue(third.confirmed && third.count == 3, "telemetry third independent session confirms")

    assertTrue(
        TelemetryLearningPolicy.isPeriodicBeacon(4, 60_000L, 5_000L),
        "stable repeated cadence recognized as beacon",
    )
    assertTrue(
        !TelemetryLearningPolicy.isPeriodicBeacon(4, 60_000L, 30_000L),
        "high-jitter cadence not labeled periodic",
    )
    assertTrue(
        !TelemetryLearningPolicy.isPeriodicBeacon(2, 60_000L, 2_000L),
        "insufficient cadence samples remain unconfirmed",
    )
    assertTrue(
        TelemetryLearningPolicy.isQueryRateShift(40, 8, 2),
        "fourfold mature telemetry rate shift detected",
    )
    assertTrue(
        !TelemetryLearningPolicy.isQueryRateShift(12, 8, 2),
        "normal telemetry rate variation remains quiet",
    )
    assertEq(TelemetryLearningPolicy.evidenceRiskPoints(80), 8, "telemetry learning XDR weight capped")
}


private fun testAsnLiteIndex() {
    val dir = java.nio.file.Files.createTempDirectory("gedefense-asn-lite").toFile()
    try {
        val v4Csv = File(dir, "v4.csv")
        val v6Csv = File(dir, "v6.csv")
        val v4Bin = File(dir, "v4.bin")
        val v6Bin = File(dir, "v6.bin")
        val orgBin = File(dir, "org.bin")
        v4Csv.writeText(
            "1.0.0.0,1.0.0.255,13335,Cloudflare Inc\n" +
                "8.8.8.0,8.8.8.255,15169,Google LLC\n" +
                "9.9.9.0,9.9.9.255,19281,\"Quad9, Foundation\"\n" +
                "10.0.0.0,10.255.255.255,0,Not routed\n",
        )
        v6Csv.writeText(
            "2001:4860::,2001:4860:ffff:ffff:ffff:ffff:ffff:ffff,15169,Google LLC\n" +
                "2606:4700::,2606:4700:ffff:ffff:ffff:ffff:ffff:ffff,13335,Cloudflare Inc\n",
        )
        val built = AsnLiteCompiler.compile(v4Csv, v6Csv, v4Bin, v6Bin, orgBin, maxRecordsPerFamily = 32)
        assertEq(built.v4Records, 3, "ASN0 ranges omitted from compact index")
        assertEq(built.v6Records, 2, "ASN IPv6 rows compiled")
        assertEq(built.organizations, 3, "ASN organization dictionary deduplicated across families")
        AsnLiteIndex.open(v4Bin, v6Bin, orgBin, built.v4Records, built.v6Records, built.organizations).use { index ->
            val google4 = index.lookup(IpPrefix.parseAddress("8.8.8.8")!!)
            assertEq(google4?.asn, 15169L, "ASN IPv4 lookup")
            assertEq(google4?.organization, "Google LLC", "ASN IPv4 organization")
            val quad9 = index.lookup(IpPrefix.parseAddress("9.9.9.9")!!)
            assertEq(quad9?.organization, "Quad9, Foundation", "quoted ASN organization CSV")
            val cloudflare6 = index.lookup(IpPrefix.parseAddress("2606:4700:4700::1111")!!)
            assertEq(cloudflare6?.asn, 13335L, "ASN IPv6 lookup")
            assertTrue(index.lookup(IpPrefix.parseAddress("10.2.3.4")!!) == null, "ASN0 remains evidence-empty")
        }

        val malformed = File(dir, "bad.csv")
        malformed.writeText("8.8.8.0,8.8.8.255,15169,Google LLC\n8.8.8.128,8.8.9.0,1,Bad overlap\n")
        var overlapRejected = false
        try {
            AsnLiteCompiler.compile(malformed, v6Csv, File(dir, "bad-v4.bin"), File(dir, "bad-v6.bin"), File(dir, "bad-org.bin"), 32)
        } catch (_: IllegalStateException) {
            overlapRejected = true
        }
        assertTrue(overlapRejected, "ASN overlapping ranges rejected")

        val boundedV4 = File(dir, "bounded-v4.csv")
        boundedV4.writeText(
            "1.0.0.0,1.0.0.0,1,Org One\n" +
                "1.0.0.1,1.0.0.1,2,Org Two\n" +
                "1.0.0.2,1.0.0.2,3,Org Three\n",
        )
        var organizationBoundRejected = false
        try {
            AsnLiteCompiler.compile(
                boundedV4,
                v6Csv,
                File(dir, "bounded-v4.bin"),
                File(dir, "bounded-v6.bin"),
                File(dir, "bounded-org.bin"),
                maxRecordsPerFamily = 32,
                maxOrganizations = 2,
            )
        } catch (_: IllegalStateException) {
            organizationBoundRejected = true
        }
        assertTrue(organizationBoundRejected, "ASN organization cardinality bounded during compile")

        val tampered = v4Bin.readBytes().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        v4Bin.writeBytes(tampered.copyOf(tampered.size - 1))
        var sizeRejected = false
        try {
            AsnLiteIndex.open(v4Bin, v6Bin, orgBin, built.v4Records, built.v6Records, built.organizations)
        } catch (_: IllegalArgumentException) {
            sizeRejected = true
        }
        assertTrue(sizeRejected, "ASN truncated binary index rejected")
    } finally {
        dir.deleteRecursively()
    }
}

fun main(){
    testNetworkRangePlanner()
    testMdnsDnsCodec()
    testLanBehaviorEvaluator()
    testPortSentinelClassifier()
    testManagedCaCertificateValidator()
    testUnavailableEvidenceStore()
    testDurableAtomicFiles()
    testAuthenticatedSnapshotStore()
    testUnavailableAuthenticatedPersistence()
    testAeadVaultEnvelope()
    testFullPolicyFingerprintDeterminism()
    testFeedCatalog(); testPrefix(); testParsers(); testRouteCompaction(); testIndex(); testPolicyEngine(); testPackets(); testFlows(); testThreatCache(); testIntegrityBaseline(); testLedger();
    testBoundedOpaqueCryptoIsolation()
    testPrivacyIntelligenceRegistry()
    testRecoveryAttemptBudget()
    testTelemetryLearningPolicy()
    testAsnLiteIndex()
    println("CORE_TESTS_PASS")
}

private fun testFeedCatalog(){
    assertEq(ThreatFeedCatalog.POLICY_ABI_VERSION, 2, "policy ABI version")
    assertEq(ThreatFeedCatalog.all.map { it.id }, listOf("feodo", "spamhaus-drop-v4", "spamhaus-drop-v6", "cins", "blocklist-de", "emerging-threats", "ipsum", "firehol-level1", "tor-exits"), "policy ABI feed order")
    assertEq(ThreatFeedCatalog.all.size,9,"feed catalog size")
    assertTrue(ThreatFeedCatalog.all.all{it.url.startsWith("https://")},"HTTPS feeds only")
    assertTrue(ThreatFeedCatalog.all.all{it.maxStaleMinutes>=it.minRefreshMinutes},"staleness >= refresh")
    assertEq(ThreatFeedCatalog.require("tor-exits").enforcement,EnforcementClass.ANNOTATE_ONLY,"Tor annotation only")
    assertEq(ThreatFeedCatalog.require("feodo").enforcement,EnforcementClass.ROUTE_BLOCK,"Feodo block authority")
    assertEq(ThreatFeedCatalog.require("spamhaus-drop-v4").enforcement,EnforcementClass.ROUTE_BLOCK,"Spamhaus v4 block authority")
    assertEq(ThreatFeedCatalog.require("spamhaus-drop-v6").enforcement,EnforcementClass.ROUTE_BLOCK,"Spamhaus v6 block authority")
    assertEq(ThreatFeedCatalog.require("firehol-level1").enforcement,EnforcementClass.ROUTE_BLOCK,"FireHOL Level 1 public-prefix block authority")
    assertTrue(ThreatFeedCatalog.all.none{it.url.contains("edrop",ignoreCase=true)},"obsolete eDROP excluded")
}

private fun testPrefix(){
    val p=IpPrefix.parse("1.2.3.0/24")!!
    assertTrue(p.contains(IpPrefix.parseAddress("1.2.3.9")!!),"v4 contain")
    assertTrue(!p.contains(IpPrefix.parseAddress("1.2.4.1")!!),"v4 reject")
    assertTrue(IpPrefix.parse("10.0.0.1")?.let{!IpPrefix.isPublic(it)}==true,"private rejected")
    val p6=IpPrefix.parse("2606:4700::/32")!!
    assertTrue(p6.contains(IpPrefix.parseAddress("2606:4700:4700::1111")!!),"v6 contain")
    assertTrue(IpPrefix.parse("2001:db8::/32")?.let{!IpPrefix.isPublic(it)}==true,"doc v6 rejected")
    assertEq(IpPrefix.parse("::ffff:8.8.8.8")?.family,4,"IPv4-mapped input canonicalized to v4")
    assertTrue(IpPrefix.parse("64:ff9b::/96")?.let{!IpPrefix.isPublic(it)}==true,"NAT64 well-known prefix rejected")
    assertTrue(IpPrefix.parse("example.com")==null,"hostname must not parse")
    assertTrue(IpPrefix.parse("0.0.0.0/0")?.let{!IpPrefix.isPublic(it)}==true,"default v4 route rejected")
    assertTrue(IpPrefix.parse("::/0")?.let{!IpPrefix.isPublic(it)}==true,"default v6 route rejected")
    assertTrue(IpPrefix.parseAddress("8.8.8.8")!!.isPublic(),"public v4 address accepted")
    assertTrue(!IpPrefix.parseAddress("10.253.0.2")!!.isPublic(),"TUN interface v4 rejected")
    assertTrue(!IpPrefix.parseAddress("224.0.0.251")!!.isPublic(),"multicast v4 rejected")
    assertTrue(!IpPrefix.parseAddress("fd7a:4744::2")!!.isPublic(),"ULA v6 rejected")
    assertTrue(!IpPrefix.parseAddress("fe80::1")!!.isPublic(),"link-local v6 rejected")
    assertTrue(!IpPrefix.parseAddress("ff02::1:ff00:1")!!.isPublic(),"DAD multicast v6 rejected")
    assertTrue(IpPrefix.parseAddress("2606:4700:4700::1111")!!.isPublic(),"public v6 address accepted")
}

private fun testParsers(){
    val feodo=ThreatFeedCatalog.require("feodo")
    val r=ThreatIntelParser.parse(feodo, sequenceOf("# c", "1.2.3.4", "10.1.2.3", "8.8.8.0/24"))
    assertEq(r.records.size,2,"plain records")
    val spam=ThreatFeedCatalog.require("spamhaus-drop-v4")
    val s=ThreatIntelParser.parse(spam,sequenceOf("{\"cidr\":\"5.6.7.0/24\",\"sblid\":\"SBL1\"}","{\"type\":\"metadata\"}"))
    assertEq(s.records.size,1,"spamhaus jsonl")
    val ipsum=ThreatFeedCatalog.require("ipsum")
    val i=ThreatIntelParser.parse(ipsum,sequenceOf("1.1.1.1\t2", "9.9.9.9\t4"))
    assertEq(i.records.size,1,"ipsum score")
    val firehol=ThreatFeedCatalog.require("firehol-level1")
    val f=ThreatIntelParser.parse(firehol, sequenceOf("10.0.0.0/8", "100.64.0.0/10", "192.168.0.0/16", "203.0.114.0/24"))
    assertEq(f.records.size,1,"FireHOL blocks only globally routable prefixes after parser safety filter")
}

private fun testRouteCompaction(){
    val v4=RouteCompactor.compact(listOf(
        IpPrefix.parse("8.8.8.0/25")!!,
        IpPrefix.parse("8.8.8.128/25")!!,
        IpPrefix.parse("1.1.1.0/24")!!,
        IpPrefix.parse("1.1.1.0/25")!!,
    ))
    assertTrue(v4.any{it.toString()=="8.8.8.0/24"},"v4 siblings compact")
    assertTrue(v4.any{it.toString()=="1.1.1.0/24"},"broader prefix preserved")
    assertEq(v4.size,2,"redundant v4 routes removed")

    val partial=RouteCompactor.compact(listOf(IpPrefix.parse("9.9.9.0/25")!!))
    assertEq(partial.single().toString(),"9.9.9.0/25","single child must not widen")

    val v6=RouteCompactor.compact(listOf(
        IpPrefix.parse("2606:4700::/33")!!,
        IpPrefix.parse("2606:4700:8000::/33")!!,
    ))
    assertEq(v6.size,1,"v6 siblings compact")
    assertEq(v6.single().prefixLength,32,"v6 parent length")
    assertTrue(v6.single().contains(IpPrefix.parseAddress("2606:4700:ffff::1")!!),"v6 compacted coverage")
}

private fun testIndex(){
    val rec=listOf(
        ThreatRecord("feodo",IpPrefix.parse("8.8.8.8")!!),
        ThreatRecord("tor-exits",IpPrefix.parse("8.8.8.8")!!),
        ThreatRecord("cins",IpPrefix.parse("1.1.1.0/24")!!)
    )
    val idx=ThreatIndex.build(rec)
    val m=idx.match("8.8.8.8")!!
    assertTrue(m.hasBlockingSignal,"blocking match")
    assertEq(m.feeds.size,2,"multi source")
    assertEq(idx.routePrefixes.size,1,"route set only block candidates")
    assertEq(idx.routeCandidateCount,1,"route candidate count")
    assertTrue(!idx.routeOverflow,"route set within bound")
    assertTrue(!idx.match("1.1.1.9")!!.hasBlockingSignal,"correlate only")
}

private fun testPolicyEngine(){
    val idx=ThreatIndex.build(listOf(
        ThreatRecord("feodo",IpPrefix.parse("8.8.8.8")!!),
        ThreatRecord("cins",IpPrefix.parse("1.1.1.1")!!),
        ThreatRecord("tor-exits",IpPrefix.parse("9.9.9.9")!!),
    ))
    val policy=PolicyEngine(idx)
    assertEq(policy.evaluate(IpPrefix.parseAddress("8.8.8.8")!!).verdict,ThreatVerdict.BLOCK,"block verdict")
    assertEq(policy.evaluate(IpPrefix.parseAddress("1.1.1.1")!!).verdict,ThreatVerdict.CORRELATE,"correlate verdict")
    assertEq(policy.evaluate(IpPrefix.parseAddress("9.9.9.9")!!).verdict,ThreatVerdict.ANNOTATE,"annotation verdict")
    assertEq(policy.evaluate(IpPrefix.parseAddress("8.8.4.4")!!).verdict,ThreatVerdict.ALLOW,"allow verdict")

    val same=ThreatIndex.build(listOf(ThreatRecord("feodo",IpPrefix.parse("8.8.8.8")!!)))
    val different=ThreatIndex.build(listOf(ThreatRecord("feodo",IpPrefix.parse("8.8.4.4")!!)))
    assertEq(idx.routePolicySha256.length,64,"policy hash length")
    assertEq(idx.routePolicySha256,same.routePolicySha256,"non-blocking evidence does not alter route policy hash")
    assertEq(same.routePolicySha256,ThreatIndex.build(listOf(ThreatRecord("feodo",IpPrefix.parse("8.8.8.8")!!))).routePolicySha256,"policy hash deterministic")
    assertTrue(idx.routePolicySha256!=different.routePolicySha256,"policy hash changes with route set")

    val oldSnapshot=PolicyEngine(ThreatIndex.build(listOf(ThreatRecord("feodo",IpPrefix.parse("8.8.8.8")!!))))
    val newSnapshot=PolicyEngine(ThreatIndex.build(listOf(ThreatRecord("feodo",IpPrefix.parse("8.8.4.4")!!))))
    val destination=IpPrefix.parseAddress("8.8.8.8")!!
    assertEq(oldSnapshot.evaluate(destination).verdict,ThreatVerdict.BLOCK,"old installed snapshot remains authoritative")
    assertEq(newSnapshot.evaluate(destination).verdict,ThreatVerdict.ALLOW,"new snapshot can differ without mutating old evaluator")
}

private fun testPackets(){
    val p=ByteArray(28)
    p[0]=0x45; p[2]=0; p[3]=28; p[9]=17
    p[12]=1;p[13]=2;p[14]=3;p[15]=4; p[16]=8;p[17]=8;p[18]=8;p[19]=8
    p[20]=0x12;p[21]=0x34;p[22]=0;p[23]=53
    p[24]=0;p[25]=8
    val x=PacketParser.parse(p)!!
    assertEq(x.destination.toString(),"8.8.8.8","packet dst")
    assertEq(x.destinationPort,53,"packet port")
}

private fun testFlows(){
    val t=FlowTable(128,10_000)
    val p=ParsedPacket(4,17,IpPrefix.parseAddress("1.1.1.1")!!,IpPrefix.parseAddress("8.8.8.8")!!,1234,53,50)
    t.observe(p,10000); val s=t.observe(p,10001)
    assertEq(s.packets,2L,"flow count")
}

private fun testThreatCache(){
    val key=SecretKeySpec(ByteArray(32){(it+3).toByte()},"HmacSHA256")
    val feed=ThreatFeedCatalog.require("feodo")
    val now=System.currentTimeMillis()

    // Commit, authenticate and reload.
    val dir=kotlin.io.path.createTempDirectory("gdm-cache-").toFile()
    try{
        val store=ThreatCacheStore(dir,key)
        val a=File(dir,"input-a").apply{writeText("8.8.8.8\n")}
        val ca=store.commit(feed,a,sha256(a),a.length(),now-2000)
        assertTrue(ca.ok,"cache commit")
        val snap=store.loadSnapshot(now)
        assertTrue(snap.match("8.8.8.8")?.hasBlockingSignal==true,"cache snapshot match")

        // Newer generation can be corrupted without making an older authenticated generation unusable.
        val b=File(dir,"input-b").apply{writeText("9.9.9.9\n")}
        val cb=store.commit(feed,b,sha256(b),b.length(),now-1000)
        assertTrue(cb.ok,"second cache commit")
        val newestData=dir.listFiles()!!.filter{it.name.startsWith("feodo-")&&it.name.endsWith(".feed")}.maxByOrNull{it.lastModified()}!!
        val raw=newestData.readBytes();raw[0]=(raw[0].toInt() xor 1).toByte();newestData.writeBytes(raw)
        val fallback=store.loadSnapshot(now)
        assertTrue(fallback.match("8.8.8.8")?.hasBlockingSignal==true,"fallback to older authenticated generation")

        // A partial generation is ignored.
        File(dir,"feodo-deadbeef-0011223344556677.feed").writeText("1.1.1.1\n")
        assertTrue(store.loadSnapshot(now).match("1.1.1.1")==null,"orphan generation ignored")
    }finally{dir.deleteRecursively()}

    // Stale dynamic intelligence must leave the active index.
    val staleDir=kotlin.io.path.createTempDirectory("gdm-cache-stale-").toFile()
    try{
        val store=ThreatCacheStore(staleDir,key)
        val f=File(staleDir,"stale-input").apply{writeText("8.8.4.4\n")}
        val fetched=now-(feed.maxStaleMinutes+1)*60_000L
        assertTrue(store.commit(feed,f,sha256(f),f.length(),fetched).ok,"stale generation can be archived")
        assertTrue(store.loadSnapshot(now).match("8.8.4.4")==null,"stale generation excluded")
    }finally{staleDir.deleteRecursively()}

    // Refuse a dramatic established-feed shrink.
    val shrinkDir=kotlin.io.path.createTempDirectory("gdm-cache-shrink-").toFile()
    try{
        val store=ThreatCacheStore(shrinkDir,key)
        val large=File(shrinkDir,"large").apply{
            writeText((1..250).joinToString("\n"){i->"8.8.${i/250}.${(i%250)+1}"}+"\n")
        }
        val first=store.commit(feed,large,sha256(large),large.length(),now-2000)
        assertTrue(first.ok&&first.records>=200,"large baseline commit")
        val tiny=File(shrinkDir,"tiny").apply{writeText("8.8.8.8\n")}
        val second=store.commit(feed,tiny,sha256(tiny),tiny.length(),now-1000)
        assertTrue(!second.ok&&second.message.contains("shrink"),"anomalous shrink refused")
    }finally{shrinkDir.deleteRecursively()}
}


private fun testIntegrityBaseline(){
    val dir=kotlin.io.path.createTempDirectory("gdm-integrity-").toFile()
    try{
        val file=File(dir,"baseline.v1")
        val key=SecretKeySpec(ByteArray(32){(it+11).toByte()},"HmacSHA256")
        val store=IntegrityBaselineStore(file,key)
        val base=IntegrityIdentity("de.visiongaia.gedefense.mobile",5,"1".repeat(64),"2".repeat(64))
        val first=store.verifyOrAdvance(base)
        assertTrue(first.ok&&first.initialized,"integrity baseline initialized")
        assertTrue(store.verifyOrAdvance(base).ok,"integrity baseline verifies")
        val tamperedInstall=base.copy(installSha256="3".repeat(64))
        assertTrue(!store.verifyOrAdvance(tamperedInstall).ok,"same-version install tamper rejected")
        val upgraded=base.copy(versionCode=6,installSha256="4".repeat(64))
        val up=store.verifyOrAdvance(upgraded)
        assertTrue(up.ok&&up.updated,"signed forward update advances baseline")
        assertTrue(!store.verifyOrAdvance(upgraded.copy(signerSha256="5".repeat(64))).ok,"signer change rejected")
        val bytes=file.readBytes(); bytes[bytes.size/2]=(bytes[bytes.size/2].toInt() xor 1).toByte(); file.writeBytes(bytes)
        assertTrue(!store.verifyOrAdvance(upgraded).ok,"baseline MAC tamper rejected")

        val migrationFile=File(dir,"baseline-migration.v1")
        val legacyKey=SecretKeySpec(ByteArray(32){(it+31).toByte()},"HmacSHA256")
        val activeKey=SecretKeySpec(ByteArray(32){(it+71).toByte()},"HmacSHA256")
        val legacyStore=IntegrityBaselineStore(migrationFile,legacyKey)
        assertTrue(legacyStore.verifyOrAdvance(base).ok,"legacy integrity baseline initialized")
        val migrationBoundary=System.currentTimeMillis()+5_000L
        val migrated=IntegrityBaselineStore(migrationFile,activeKey,recoveryBoundaryMillis=migrationBoundary)
            .verifyOrAdvance(upgraded)
        assertTrue(migrated.ok&&migrated.reason=="integrity_update_key_recovered","pre-update integrity key migration recovers")
        assertTrue(IntegrityBaselineStore(migrationFile,activeKey).verifyOrAdvance(upgraded).ok,"migrated integrity baseline authenticates")

        val lateFile=File(dir,"baseline-post-update-tamper.v1")
        assertTrue(IntegrityBaselineStore(lateFile,legacyKey).verifyOrAdvance(base).ok,"late baseline initialized")
        val oldBoundary=System.currentTimeMillis()-10_000L
        lateFile.setLastModified(System.currentTimeMillis())
        val notRecovered=IntegrityBaselineStore(lateFile,activeKey,recoveryBoundaryMillis=oldBoundary).verifyOrAdvance(upgraded)
        assertTrue(!notRecovered.ok&&notRecovered.reason=="integrity_baseline_authentication_failed","post-update baseline tamper is never healed")
    }finally{dir.deleteRecursively()}
}

private fun sha256(file:File):String{
    val d=MessageDigest.getInstance("SHA-256")
    file.inputStream().use{input->val b=ByteArray(8192);while(true){val n=input.read(b);if(n<0)break;d.update(b,0,n)}}
    return d.digest().joinToString(""){"%02x".format(it)}
}

private fun testAeadVaultEnvelope() {
    val key = SecretKeySpec(ByteArray(32) { (it * 7 + 11).toByte() }, "AES")
    val plaintext = "package=com.example.secret\ndomain=private.example\nscore=91".toByteArray()
    val envelope = AeadVaultEnvelope.seal(
        key = key,
        domain = "behavior-baseline",
        binding = "behavior_baseline.snapshot",
        schemaVersion = 3,
        keyVersion = 2,
        plaintext = plaintext,
    )
    assertTrue(AeadVaultEnvelope.isEnvelope(envelope), "vault envelope recognized")
    assertEq(AeadVaultEnvelope.peekKeyVersion(envelope), 2, "vault key version readable")
    assertTrue(!String(envelope, Charsets.ISO_8859_1).contains("com.example.secret"), "vault plaintext absent")

    val opened = AeadVaultEnvelope.open(
        key = key,
        domain = "behavior-baseline",
        binding = "behavior_baseline.snapshot",
        expectedSchemaVersion = 3,
        envelope = envelope,
        maxPlaintextBytes = 4096,
        maxKeyVersion = 2,
    )
    assertEq(String(opened.plaintext), String(plaintext), "vault round trip")
    assertEq(opened.keyVersion, 2, "vault opened key version")
    opened.plaintext.fill(0)

    fun mustReject(label: String, block: () -> Unit) {
        try {
            block()
            throw AssertionError("$label: expected rejection")
        } catch (_: java.security.GeneralSecurityException) {
            // expected
        }
    }

    val tampered = envelope.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
    mustReject("vault ciphertext tamper") {
        AeadVaultEnvelope.open(key, "behavior-baseline", "behavior_baseline.snapshot", 3, tampered, 4096, 2)
    }
    mustReject("vault wrong domain") {
        AeadVaultEnvelope.open(key, "xdr-events", "behavior_baseline.snapshot", 3, envelope, 4096, 2)
    }
    mustReject("vault wrong binding") {
        AeadVaultEnvelope.open(key, "behavior-baseline", "other.snapshot", 3, envelope, 4096, 2)
    }
    mustReject("vault wrong schema") {
        AeadVaultEnvelope.open(key, "behavior-baseline", "behavior_baseline.snapshot", 4, envelope, 4096, 2)
    }
    mustReject("vault future key version") {
        AeadVaultEnvelope.open(key, "behavior-baseline", "behavior_baseline.snapshot", 3, envelope, 4096, 1)
    }
    plaintext.fill(0)
    envelope.fill(0)
    tampered.fill(0)
}

private fun testLedger(){
    val dir=kotlin.io.path.createTempDirectory("gdm-ledger-").toFile()
    try{
        val f=File(dir,"events.log"); val key=SecretKeySpec(ByteArray(32){it.toByte()},"HmacSHA256")
        val l=EvidenceLedger(f,key,1L shl 20)
        assertTrue(l.open().ok,"empty healthy")
        l.append(EvidenceEvent("threat.block","high","8.8.8.8","feed=feodo"))
        l.append(EvidenceEvent("vpn.state","info","local","active"))
        assertEq(l.verify().records,2L,"ledger records")
        val bytes=f.readBytes(); bytes[bytes.size/2]=(bytes[bytes.size/2].toInt() xor 1).toByte(); f.writeBytes(bytes)
        assertTrue(!l.verify().ok,"tamper detected")
        val rr=l.recover(File(dir,"recovery"),"Operator confirmed integrity recovery")
        assertTrue(rr.archive.exists()&&rr.manifest.exists(),"archive exists")
        assertTrue(l.verifyRecoveryArchive(rr.manifest).ok,"recovery archive verifies")
        assertTrue(l.verify().ok,"fresh ledger healthy")

        val manifestBytes=rr.manifest.readBytes()
        manifestBytes[manifestBytes.size/2]=(manifestBytes[manifestBytes.size/2].toInt() xor 1).toByte()
        rr.manifest.writeBytes(manifestBytes)
        assertTrue(!l.verifyRecoveryArchive(rr.manifest).ok,"recovery manifest tamper detected")


        // A healthy legacy v2 ledger is atomically upgraded to encrypted v3 before plaintext is returned.
        val migrationFile=File(dir,"migration.log")
        val legacy=EvidenceLedger(migrationFile,key,1L shl 20)
        legacy.append(EvidenceEvent("behavior.anomaly","high","com.example.secret","domain=example.test"))
        assertTrue(!migrationFile.readText().startsWith("3|"),"legacy fixture is v2")
        val aes=SecretKeySpec(ByteArray(32){(it+33).toByte()},"AES")
        val protector=object:EvidencePayloadProtector{
            override fun protect(sequence:Long,atMillis:Long,plaintext:ByteArray):ByteArray{
                val nonce=ByteArray(12)
                java.nio.ByteBuffer.wrap(nonce).putLong(sequence).putInt((atMillis xor (atMillis ushr 32)).toInt())
                val c=Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.ENCRYPT_MODE,aes,GCMParameterSpec(128,nonce))
                c.updateAAD("$sequence:$atMillis".toByteArray())
                return nonce+c.doFinal(plaintext)
            }
            override fun unprotect(sequence:Long,atMillis:Long,protectedPayload:ByteArray):ByteArray{
                val nonce=protectedPayload.copyOfRange(0,12)
                val c=Cipher.getInstance("AES/GCM/NoPadding")
                c.init(Cipher.DECRYPT_MODE,aes,GCMParameterSpec(128,nonce))
                c.updateAAD("$sequence:$atMillis".toByteArray())
                return c.doFinal(protectedPayload,12,protectedPayload.size-12)
            }
        }
        val encrypted=EvidenceLedger(migrationFile,key,1L shl 20,protector)
        assertTrue(encrypted.open().ok,"legacy evidence encrypted migration succeeds")
        assertEq(encrypted.verify().records,1L,"encrypted evidence record survives migration")
        val migratedText=migrationFile.readText()
        assertTrue(migratedText.startsWith("3|"),"evidence migrated to v3")
        assertTrue(!migratedText.contains("com.example.secret")&&!migratedText.contains("example.test"),"evidence plaintext absent")

        // High-throughput HMAC key rotation must preserve encrypted payloads while rebuilding
        // the independent chain under the new key.
        val rotatedKey=SecretKeySpec(ByteArray(32){(it+91).toByte()},"HmacSHA256")
        val rotatedHealth=encrypted.rotateAuthenticationKey(rotatedKey)
        assertTrue(rotatedHealth.ok&&rotatedHealth.records==1L,"evidence HMAC rotation succeeds")
        assertTrue(!encrypted.verify().ok,"old evidence HMAC key rejected after rotation")
        val rotatedLedger=EvidenceLedger(migrationFile,rotatedKey,1L shl 20,protector)
        assertTrue(rotatedLedger.open().ok,"rotated evidence HMAC key verifies")
        assertEq(rotatedLedger.verify().records,1L,"rotated evidence record survives")

        val migratedBytes=migrationFile.readBytes(); migratedBytes[migratedBytes.size/2]=(migratedBytes[migratedBytes.size/2].toInt() xor 1).toByte(); migrationFile.writeBytes(migratedBytes)
        assertTrue(!rotatedLedger.verify().ok,"encrypted evidence tamper detected")
    }finally{dir.deleteRecursively()}
}
