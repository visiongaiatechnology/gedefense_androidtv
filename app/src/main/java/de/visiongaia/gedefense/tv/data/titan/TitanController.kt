package de.visiongaia.gedefense.tv.data.titan

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.util.Log
import de.visiongaia.gedefense.mobile.core.ThreatIndex
import de.visiongaia.gedefense.tv.contract.SettingsApi
import de.visiongaia.gedefense.tv.contract.TitanActionResultListener
import de.visiongaia.gedefense.tv.contract.TitanActivationListener
import de.visiongaia.gedefense.tv.contract.TitanApi
import de.visiongaia.gedefense.tv.contract.TitanScanListener
import de.visiongaia.gedefense.tv.contract.TitanUiState
import de.visiongaia.gedefense.tv.contract.TitanWitnessListener
import de.visiongaia.gedefense.tv.core.model.DataVisibility
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.titan.TitanCapabilityMatrix
import de.visiongaia.gedefense.tv.core.titan.TitanStatusComposer
import de.visiongaia.gedefense.tv.core.titan.model.FimSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.SocketSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionFailure
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionRequest
import de.visiongaia.gedefense.tv.core.titan.model.TitanActionResult
import de.visiongaia.gedefense.tv.core.titan.model.TitanCapability
import de.visiongaia.gedefense.tv.core.titan.model.TitanContainmentAction
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeLevel
import de.visiongaia.gedefense.tv.core.titan.model.TitanPrivilegeSnapshot
import de.visiongaia.gedefense.tv.core.titan.model.TitanScanOutcome
import de.visiongaia.gedefense.tv.core.titan.model.TitanStatus
import de.visiongaia.gedefense.tv.core.titan.model.TitanTextKeys
import de.visiongaia.gedefense.tv.core.titan.model.TitanVaultEntry
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessCheckpoint
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessState
import de.visiongaia.gedefense.tv.core.titan.model.TitanWitnessStatus
import de.visiongaia.gedefense.tv.core.titan.response.TitanContainmentPolicy
import de.visiongaia.gedefense.tv.data.TvEvidenceRepository
import de.visiongaia.gedefense.tv.data.TvTitanStore
import de.visiongaia.gedefense.tv.platform.titan.collect.TitanFimCollector
import de.visiongaia.gedefense.tv.platform.titan.collect.TitanSocketCollector
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanPrivilegeGate
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanResponseEngine
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanShell
import de.visiongaia.gedefense.tv.platform.titan.privilege.TitanShizukuClient
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Process-wide implementation of [TitanApi].
 *
 * Owns the bounded Titan worker (one scan/activation/action at a time), the cached [TitanStatus]
 * snapshot (UI-thread safe), local persistence and the evidence trail.
 *
 * Privilege honesty rules:
 *  - a passive scan never raises the level and never prompts for Superuser;
 *  - only [activate] runs the explicit root confirmation probe;
 *  - inside one process lifetime a previously confirmed channel is reused (no repeated prompt),
 *    after a restart the level honestly falls back to STANDARD until the user activates again.
 */
class TitanController(
    context: Context,
    private val settings: SettingsApi,
    evidence: TvEvidenceRepository,
    threatIndexProvider: () -> ThreatIndex,
    private val deviceId: String,
    private val osApiLevel: Int,
    private val clock: () -> Long = { System.currentTimeMillis() },
) : TitanApi {
    private val appContext = context.applicationContext
    private val shell = TitanShell(appContext)
    private val gate = TitanPrivilegeGate(appContext)
    private val policy = TitanContainmentPolicy(
        selfPackage = appContext.packageName,
        selfUid = android.os.Process.myUid(),
        selfPid = android.os.Process.myPid(),
        clock = clock,
    )
    private val response = TitanResponseEngine(appContext, shell, policy, clock)
    private val store = TvTitanStore(appContext, deviceId)
    private val recorder = TitanEvidenceRecorder(deviceId, osApiLevel, evidence)
    private val witness = TitanWitnessCoordinator(deviceId, evidence, store, recorder, clock)
    private val socketCollector = TitanSocketCollector(appContext, { shell }, threatIndexProvider)
    private val fimCollector = TitanFimCollector(appContext, { shell }, store)
    private val executor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-titan").apply {
            isDaemon = true
            priority = Thread.MIN_PRIORITY
        }
    }
    private val mainHandler = Handler(Looper.getMainLooper())

    private val scanning = AtomicBoolean(false)
    private val activationBusy = AtomicBoolean(false)
    private val actionBusy = AtomicBoolean(false)
    private val containmentLock = Any()
    private val activeContainments = LinkedHashSet<String>()

    @Volatile
    private var cachedStatus: TitanStatus = loadInitialStatus()

    @Volatile
    private var lastCheckpoint: TitanWitnessCheckpoint? = null

    init {
        TitanShizukuClient.addDeathListener {
            executor.execute { handleShizukuBinderDied() }
        }
        executor.execute { warmUp() }
    }

    private fun handleShizukuBinderDied() {
        val current = cachedStatus.privilege ?: return
        if (current.level != TitanPrivilegeLevel.SHIZUKU) return
        shell.setChannelMode(TitanShell.ChannelMode.ROOT)
        val downgraded = current.copy(
            level = TitanPrivilegeLevel.STANDARD,
            shizukuBridgeAvailable = false,
            checkedAtMillis = clock().coerceAtLeast(1L),
            notes = listOf(MessageRef(TitanTextKeys.NOTE_SHIZUKU_BRIDGE_MISSING)),
        )
        publishPrivilege(downgraded)
    }

    private fun warmUp() {
        try {
            if (scanning.get()) return
            val now = clock()
            val snapshot = gate.passiveSnapshot(now)
            publish(composeFrom(activePrivilege(snapshot, confirmed = false), cachedStatus.sockets, cachedStatus.fim, cachedStatus.witness, now))
        } catch (error: Throwable) {
            Log.w(TAG, "titan warm-up failed: ${describe(error)}")
        }
    }

    // ------------------------------------------------------------------ status / ui state

    override fun status(): TitanStatus = cachedStatus

    override fun state(): TitanUiState = TitanUiState(scanning.get(), cachedStatus.lastScanAtMillis)

    override fun vaultEntries(): List<TitanVaultEntry> = store.vaultEntries()

    override fun witnessStatus(): TitanWitnessStatus = cachedStatus.witness

    override fun latestCheckpoint(): TitanWitnessCheckpoint? = lastCheckpoint

    // ------------------------------------------------------------------ scans

    override fun scanNow(listener: TitanScanListener): Boolean {
        if (!scanning.compareAndSet(false, true)) return false
        post { listener.onStarted() }
        executor.execute {
            val startedAt = clock()
            try {
                publish(TitanStatusComposer.running(status(), startedAt))
                val socketGuard = settings.titanSocketGuardEnabled()
                val fimGuard = settings.titanFimGuardEnabled()
                val total = 2 + (if (socketGuard) 1 else 0) + (if (fimGuard) 1 else 0)
                var step = 0

                // Passive detection only: a scan never prompts. A channel confirmed in this process
                // is reused without a second Superuser dialog.
                val passive = gate.passiveSnapshot(startedAt)
                val privilege = activePrivilege(passive, confirmed = shouldReuseConfirmation(passive))
                val capabilities = TitanCapabilityMatrix.effectiveCapabilities(privilege)
                step += 1
                post { listener.onProgress(step, total) }

                val sockets = collectSockets(socketGuard, capabilities, privilege)
                step += 1
                post { listener.onProgress(step, total) }

                val fim = collectFim(fimGuard, capabilities, privilege)
                step += 1
                post { listener.onProgress(step, total) }

                val witnessRefresh = witness.refresh(clock())
                lastCheckpoint = witnessRefresh.checkpoint
                step += 1
                post { listener.onProgress(step, total) }

                val completedAt = clock()
                val degraded = sockets.visibility == DataVisibility.PARTIAL || fim.visibility == DataVisibility.PARTIAL
                val status = TitanStatusComposer.compose(
                    privilege = privilege,
                    sockets = sockets,
                    fim = fim,
                    witness = witnessRefresh.status,
                    activeContainments = activeContainmentCount(),
                    lastScanAtMillis = completedAt,
                    lastScanOutcome = if (degraded) TitanScanOutcome.PARTIAL else TitanScanOutcome.COMPLETED,
                    nowMillis = completedAt,
                )
                publish(status)
                recorder.recordScan(privilege, sockets, fim, completedAt)
                Log.i(TAG, "titan scan ms=${completedAt - startedAt} level=${privilege.level.name} caps=${capabilities.size}")
                post { listener.onCompleted(status) }
            } catch (error: Throwable) {
                Log.w(TAG, "titan scan failed: ${describe(error)}")
                publish(cachedStatus.copy(lastScanAtMillis = clock(), lastScanOutcome = TitanScanOutcome.FAILED))
                post { listener.onFailed(MessageRef(TitanTextKeys.KEY_SCAN_FAILED)) }
            } finally {
                scanning.set(false)
            }
        }
        return true
    }

    private fun shouldReuseConfirmation(passive: TitanPrivilegeSnapshot): Boolean {
        val last = cachedStatus.privilege ?: return false
        if (!settings.titanConsentGranted()) return false
        return when (last.level) {
            TitanPrivilegeLevel.ROOT ->
                last.rootShellConfirmed &&
                    (passive.suPaths.isNotEmpty() || passive.rootManagers.isNotEmpty() || last.suPaths.isNotEmpty())
            TitanPrivilegeLevel.SHIZUKU ->
                last.shizukuBridgeAvailable && TitanShizukuClient.isChannelReady(appContext)
            TitanPrivilegeLevel.STANDARD -> false
        }
    }

    /**
     * Keeps a previously confirmed privileged channel alive for this process without prompting
     * again. Passive build facts are always refreshed; the confirmed channel fields are carried
     * over and [shell] channel mode stays synchronized.
     */
    private fun activePrivilege(passive: TitanPrivilegeSnapshot, confirmed: Boolean): TitanPrivilegeSnapshot {
        if (!confirmed) return passive
        val last = cachedStatus.privilege ?: return passive
        return when (last.level) {
            TitanPrivilegeLevel.ROOT -> {
                shell.setChannelMode(TitanShell.ChannelMode.ROOT)
                last.copy(
                    level = TitanPrivilegeLevel.ROOT,
                    rootShellConfirmed = true,
                    checkedAtMillis = passive.checkedAtMillis,
                    build = passive.build,
                    suPaths = if (passive.suPaths.isEmpty()) last.suPaths else passive.suPaths,
                    rootManagers = if (passive.rootManagers.isEmpty()) last.rootManagers else passive.rootManagers,
                    notes = passive.notes,
                )
            }
            TitanPrivilegeLevel.SHIZUKU -> {
                shell.setChannelMode(TitanShell.ChannelMode.SHIZUKU)
                last.copy(
                    level = TitanPrivilegeLevel.SHIZUKU,
                    shizukuInstalled = passive.shizukuInstalled || last.shizukuInstalled,
                    shizukuBridgeAvailable = true,
                    checkedAtMillis = passive.checkedAtMillis,
                    build = passive.build,
                    notes = passive.notes,
                )
            }
            TitanPrivilegeLevel.STANDARD -> passive
        }
    }

    private fun collectSockets(
        guardEnabled: Boolean,
        capabilities: Set<TitanCapability>,
        privilege: TitanPrivilegeSnapshot,
    ): SocketSnapshot = try {
        if (guardEnabled && TitanCapability.SOCKET_PROVENANCE in capabilities) {
            socketCollector.collect(privilege, clock())
        } else {
            SocketSnapshot.empty(clock(), DataVisibility.PARTIAL, MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED))
        }
    } catch (error: Throwable) {
        Log.w(TAG, "titan socket collect failed: ${describe(error)}")
        SocketSnapshot.empty(clock(), DataVisibility.PARTIAL, MessageRef(TitanTextKeys.NOTE_SOCKET_LIMITED))
    }

    private fun collectFim(
        guardEnabled: Boolean,
        capabilities: Set<TitanCapability>,
        privilege: TitanPrivilegeSnapshot,
    ): FimSnapshot = try {
        if (guardEnabled && TitanCapability.DEEP_INVENTORY_FIM in capabilities) {
            fimCollector.collect(privilege, clock())
        } else {
            FimSnapshot.empty(clock(), DataVisibility.PARTIAL, MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE))
        }
    } catch (error: Throwable) {
        Log.w(TAG, "titan fim collect failed: ${describe(error)}")
        FimSnapshot.empty(clock(), DataVisibility.PARTIAL, MessageRef(TitanTextKeys.NOTE_FIM_UNREADABLE))
    }

    // ------------------------------------------------------------------ privilege activation

    override fun refreshPrivilege(listener: TitanActivationListener): Boolean {
        if (!activationBusy.compareAndSet(false, true)) return false
        executor.execute {
            try {
                val snapshot = gate.passiveSnapshot(clock())
                publishPrivilege(activePrivilege(snapshot, confirmed = false))
                post {
                    listener.onResult(
                        snapshot,
                        MessageRef(
                            when {
                                snapshot.suPaths.isNotEmpty() -> TitanTextKeys.NOTE_ROOT_DETECTED
                                snapshot.shizukuInstalled -> TitanTextKeys.NOTE_SHIZUKU_DETECTED
                                else -> TitanTextKeys.NOTE_STANDARD_ONLY
                            },
                        ),
                    )
                }
            } catch (error: Throwable) {
                Log.w(TAG, "titan privilege refresh failed: ${describe(error)}")
                post { listener.onResult(null, MessageRef(TitanTextKeys.NOTE_STANDARD_ONLY)) }
            } finally {
                activationBusy.set(false)
            }
        }
        return true
    }

    override fun activate(listener: TitanActivationListener): Boolean {
        if (!activationBusy.compareAndSet(false, true)) return false
        executor.execute {
            try {
                val now = clock()
                var snapshot = gate.passiveSnapshot(now)
                val hasSu = snapshot.suPaths.isNotEmpty() || snapshot.rootManagers.isNotEmpty()
                val hasShizuku = snapshot.shizukuInstalled
                if (!hasSu && !hasShizuku) {
                    shell.setChannelMode(TitanShell.ChannelMode.ROOT)
                    publishPrivilege(snapshot)
                    post { listener.onResult(snapshot, MessageRef(TitanTextKeys.KEY_ACTIVATE_NO_CHANNEL)) }
                    return@execute
                }
                if (hasSu) {
                    shell.setChannelMode(TitanShell.ChannelMode.ROOT)
                    val confirmed = gate.confirmRoot(snapshot, shell, clock())
                    if (confirmed.level == TitanPrivilegeLevel.ROOT && confirmed.rootShellConfirmed) {
                        settings.setTitanConsentGranted(true)
                        publishPrivilege(confirmed)
                        recorder.recordPrivilege(confirmed, clock())
                        post { listener.onResult(confirmed, MessageRef(TitanTextKeys.KEY_ACTIVATE_OK)) }
                        return@execute
                    }
                    if (!hasShizuku) {
                        publishPrivilege(confirmed)
                        post { listener.onResult(confirmed, MessageRef(TitanTextKeys.KEY_ACTIVATE_DENIED)) }
                        return@execute
                    }
                    snapshot = confirmed
                }
                // Level 2 (Shizuku): real binder attach, permission confirmation, and `id` probe.
                val confirmedShizuku = gate.confirmShizuku(snapshot, shell, clock())
                if (confirmedShizuku.level == TitanPrivilegeLevel.SHIZUKU && confirmedShizuku.shizukuBridgeAvailable) {
                    shell.setChannelMode(TitanShell.ChannelMode.SHIZUKU)
                    settings.setTitanConsentGranted(true)
                    publishPrivilege(confirmedShizuku)
                    recorder.recordPrivilege(confirmedShizuku, clock())
                    post { listener.onResult(confirmedShizuku, MessageRef(TitanTextKeys.KEY_ACTIVATE_SHIZUKU_OK)) }
                } else {
                    shell.setChannelMode(TitanShell.ChannelMode.ROOT)
                    publishPrivilege(confirmedShizuku)
                    val key = if (confirmedShizuku.shizukuBridgeAvailable) {
                        TitanTextKeys.KEY_ACTIVATE_DENIED
                    } else {
                        TitanTextKeys.KEY_ACTIVATE_BRIDGE_UNAVAILABLE
                    }
                    post { listener.onResult(confirmedShizuku, MessageRef(key)) }
                }
            } catch (error: Throwable) {
                Log.w(TAG, "titan activation failed: ${describe(error)}")
                post { listener.onResult(null, MessageRef(TitanTextKeys.KEY_ACTIVATE_DENIED)) }
            } finally {
                activationBusy.set(false)
            }
        }
        return true
    }

    // ------------------------------------------------------------------ containment

    override fun contain(request: TitanActionRequest, listener: TitanActionResultListener): Boolean {
        if (!actionBusy.compareAndSet(false, true)) return false
        executor.execute {
            try {
                val capabilities = TitanCapabilityMatrix.effectiveCapabilities(cachedStatus.privilege)
                val result = if (!settings.titanConsentGranted()) {
                    // Defense in depth: no containment without an explicit, persisted user consent,
                    // even if a stale status carried a privileged level.
                    TitanActionResult(
                        action = request.action,
                        target = request.target,
                        executedAtMillis = clock(),
                        ok = false,
                        verified = false,
                        failure = TitanActionFailure.NOT_AUTHORIZED,
                        detail = "consent-missing",
                    )
                } else {
                    response.execute(request, capabilities, activeContainmentCount())
                }
                updateActiveContainments(request, result)
                publish(cachedStatus.copy(activeContainments = activeContainmentCount()))
                recorder.recordActionResult(result, request.reason.name, clock())
                post { listener.onResult(result) }
            } catch (error: Throwable) {
                Log.w(TAG, "titan containment failed: ${describe(error)}")
                post { listener.onResult(controllerFailure(request)) }
            } finally {
                actionBusy.set(false)
            }
        }
        return true
    }

    private fun updateActiveContainments(request: TitanActionRequest, result: TitanActionResult) {
        if (!result.ok) return
        synchronized(containmentLock) {
            when (request.action) {
                TitanContainmentAction.RESTORE_APP, TitanContainmentAction.RELEASE_NETWORK_UID ->
                    activeContainments.remove(request.target.identity())

                // A killed PID can be reused; never keep it in the active set (fail-safe bookkeeping).
                TitanContainmentAction.KILL_PROCESS -> Unit

                TitanContainmentAction.FREEZE_APP, TitanContainmentAction.ISOLATE_NETWORK_UID ->
                    activeContainments.add(request.target.identity())

                TitanContainmentAction.CLOSE_ADB_PORT -> Unit
            }
        }
    }

    private fun controllerFailure(request: TitanActionRequest): TitanActionResult = TitanActionResult(
        action = request.action,
        target = request.target,
        executedAtMillis = clock(),
        ok = false,
        verified = false,
        failure = TitanActionFailure.UNAVAILABLE,
        detail = "controller-error",
    )

    // ------------------------------------------------------------------ witness protocol

    override fun refreshWitnessCheckpoint(listener: TitanWitnessListener?): Boolean {
        executor.execute {
            try {
                val refresh = witness.refresh(clock())
                lastCheckpoint = refresh.checkpoint
                publish(cachedStatus.copy(witness = refresh.status))
                val ok = refresh.status.state != TitanWitnessState.UNAVAILABLE
                post {
                    listener?.onResult(
                        ok,
                        refresh.status,
                        MessageRef(if (ok) TitanTextKeys.KEY_WITNESS_OK else TitanTextKeys.KEY_WITNESS_UNAVAILABLE),
                    )
                }
            } catch (error: Throwable) {
                Log.w(TAG, "titan witness refresh failed: ${describe(error)}")
                post {
                    listener?.onResult(
                        false,
                        TitanWitnessStatus.UNAVAILABLE,
                        MessageRef(TitanTextKeys.KEY_WITNESS_UNAVAILABLE),
                    )
                }
            }
        }
        return true
    }

    // ------------------------------------------------------------------ internal helpers

    private fun publishPrivilege(snapshot: TitanPrivilegeSnapshot) {
        publish(composeFrom(snapshot, cachedStatus.sockets, cachedStatus.fim, cachedStatus.witness, clock()))
    }

    private fun composeFrom(
        privilege: TitanPrivilegeSnapshot,
        sockets: SocketSnapshot?,
        fim: FimSnapshot?,
        witnessStatus: TitanWitnessStatus,
        nowMillis: Long,
    ): TitanStatus = TitanStatusComposer.compose(
        privilege = privilege,
        sockets = sockets,
        fim = fim,
        witness = witnessStatus,
        activeContainments = activeContainmentCount(),
        lastScanAtMillis = cachedStatus.lastScanAtMillis,
        lastScanOutcome = cachedStatus.lastScanOutcome,
        nowMillis = nowMillis,
    )

    private fun publish(status: TitanStatus) {
        cachedStatus = status
        try {
            store.saveStatus(status)
        } catch (error: Throwable) {
            Log.w(TAG, "titan store failed: ${describe(error)}")
        }
    }

    private fun activeContainmentCount(): Int = synchronized(containmentLock) { activeContainments.size }

    private fun loadInitialStatus(): TitanStatus = try {
        val stored = store.loadStatus(deviceId)
        if (stored == null) {
            TitanStatus.empty(clock())
        } else if (stored.level != TitanPrivilegeLevel.STANDARD) {
            // A persisted ROOT or SHIZUKU level is privilege EVIDENCE, not a confirmation for this process.
            // Cold start honestly falls back to Level 1 until the user activates again.
            stored.copy(
                level = TitanPrivilegeLevel.STANDARD,
                visibility = DataVisibility.PARTIAL,
                capabilities = emptySet(),
                privilege = stored.privilege?.copy(
                    level = TitanPrivilegeLevel.STANDARD,
                    rootShellConfirmed = false,
                    shizukuBridgeAvailable = false,
                ),
            )
        } else {
            stored.copy(
                privilege = stored.privilege?.copy(shizukuBridgeAvailable = false),
            )
        }
    } catch (_: Throwable) {
        TitanStatus.empty(clock())
    }

    private fun post(block: () -> Unit) {
        mainHandler.post {
            try {
                block()
            } catch (error: Throwable) {
                Log.w(TAG, "titan listener failed: ${describe(error)}")
            }
        }
    }

    private fun describe(error: Throwable): String {
        val message = error.message.orEmpty()
            .map { if (it == '\n' || it == '\r') ' ' else it }
            .joinToString("")
            .trim()
            .take(120)
        return "${error::class.java.simpleName}: $message"
    }

    private companion object {
        const val TAG = "GeDefenseTvTitan"
    }
}
