package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.ComponentName
import android.content.Context
import android.content.pm.PackageManager
import android.os.Bundle
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import de.visiongaia.gedefense.tv.BuildConfig
import de.visiongaia.gedefense.tv.core.titan.response.TitanShellCommand
import moe.shizuku.server.IRemoteProcess
import moe.shizuku.server.IShizukuApplication
import moe.shizuku.server.IShizukuService
import moe.shizuku.server.IShizukuServiceConnection
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/**
 * Zero-dependency Shizuku IPC client for Titan Level 2 (`SHIZUKU`).
 *
 * Receives the [IShizukuService] binder from [TitanShizukuProvider] (or falls back to a
 * guarded `ServiceManager.getService("shizuku")` lookup), completes the Shizuku `attachApplication`
 * handshake, handles asynchronous permission confirmation (`requestPermission`), and executes
 * strictly allowlisted Level-2 commands via [TitanShizukuUserService] (preferring Shizuku's modern
 * UserService API, with bounded `newProcess` fallback when older servers lack UserService).
 *
 * Binder death clears all elevated state fail-closed and triggers registered death listeners so
 * [TitanController] immediately degrades back to Level 1 (`STANDARD`).
 */
object TitanShizukuClient {

    enum class PermissionState {
        UNAVAILABLE,
        GRANTED,
        DENIED,
        TIMEOUT,
    }

    private val lock = Any()
    private val deathListeners = CopyOnWriteArrayList<() -> Unit>()
    private val nextRequestCode = AtomicInteger(400)

    @Volatile
    private var binder: IBinder? = null

    @Volatile
    private var service: IShizukuService? = null

    @Volatile
    private var attached = false

    @Volatile
    private var permissionGranted = false

    @Volatile
    private var serverUid = -1

    @Volatile
    private var serverApiVersion = -1

    @Volatile
    private var userBridge: ITitanShizukuBridge? = null

    @Volatile
    private var userServiceConnection: IShizukuServiceConnection? = null

    @Volatile
    private var bindLatch: CountDownLatch? = null

    @Volatile
    private var permissionLatch: CountDownLatch? = null

    @Volatile
    private var pendingPermissionCode = -1

    @Volatile
    private var pendingPermissionAllowed = false

    @Volatile
    private var userServiceLatch: CountDownLatch? = null

    private val applicationStub = object : IShizukuApplication.Stub() {
        override fun bindApplication(data: Bundle?) {
            if (data != null) {
                serverUid = data.getInt(KEY_REPLY_UID, -1)
                serverApiVersion = data.getInt(KEY_REPLY_VERSION, -1)
                permissionGranted = data.getBoolean(KEY_REPLY_PERMISSION_GRANTED, false)
            }
            attached = true
            bindLatch?.countDown()
        }

        override fun dispatchRequestPermissionResult(requestCode: Int, data: Bundle?) {
            val allowed = data?.getBoolean(KEY_PERMISSION_ALLOWED, false) ?: false
            if (requestCode == pendingPermissionCode) {
                pendingPermissionAllowed = allowed
                if (allowed) permissionGranted = true
                permissionLatch?.countDown()
            }
        }

        override fun showPermissionConfirmation(
            requestUid: Int,
            requestPid: Int,
            requestPackageName: String?,
            requestCode: Int,
        ) {
            // Managed by Shizuku manager on Android TV.
        }
    }

    private val deathRecipient = IBinder.DeathRecipient {
        clearState(notifyListeners = true)
    }

    fun addDeathListener(listener: () -> Unit) {
        deathListeners.addIfAbsent(listener)
    }

    fun removeDeathListener(listener: () -> Unit) {
        deathListeners.remove(listener)
    }

    fun currentBinder(): IBinder? = synchronized(lock) {
        val b = binder
        if (b != null && b.pingBinder()) b else null
    }

    fun isBinderAlive(): Boolean = currentBinder() != null

    fun isChannelReady(context: Context): Boolean {
        if (!tryDiscoverBinder(context)) return false
        val svc = synchronized(lock) { service } ?: return false
        return try {
            permissionGranted || svc.checkSelfPermission()
        } catch (_: Throwable) {
            false
        }
    }

    fun serverUid(): Int = serverUid

    fun onBinderReceived(newBinder: IBinder, packageName: String) {
        synchronized(lock) {
            if (binder === newBinder && newBinder.pingBinder()) return
            clearLocked()
            binder = newBinder
            service = IShizukuService.Stub.asInterface(newBinder)
            try {
                newBinder.linkToDeath(deathRecipient, 0)
            } catch (_: Throwable) {
                // Dead already; next ping/call detects it cleanly.
            }
        }
        attachHandshake(newBinder, packageName)
    }

    /** Attempts to ensure a live, attached [IShizukuService] binder using provider push or ServiceManager. */
    fun tryDiscoverBinder(context: Context): Boolean {
        val current = synchronized(lock) { binder }
        if (current != null) {
            if (current.pingBinder()) {
                if (!attached) attachHandshake(current, context.packageName)
                return true
            }
            clearState(notifyListeners = true)
        }
        val discovered = lookupViaServiceManager() ?: return false
        if (!discovered.pingBinder()) return false
        onBinderReceived(discovered, context.packageName)
        return isBinderAlive()
    }

    /** Verifies or interactively requests Shizuku permission for this app (bounded wait). */
    fun ensurePermission(context: Context, timeoutMillis: Long = PERMISSION_WAIT_MS): PermissionState {
        if (!tryDiscoverBinder(context)) return PermissionState.UNAVAILABLE
        val svc = synchronized(lock) { service } ?: return PermissionState.UNAVAILABLE
        try {
            if (permissionGranted || svc.checkSelfPermission()) {
                permissionGranted = true
                return PermissionState.GRANTED
            }
        } catch (sec: SecurityException) {
            Log.w(TAG, "shizuku checkSelfPermission rejected: ${sec.javaClass.simpleName}")
        } catch (_: Throwable) {
            return PermissionState.UNAVAILABLE
        }
        if (context.checkSelfPermission(SHIZUKU_PERMISSION) == PackageManager.PERMISSION_GRANTED) {
            try {
                if (svc.checkSelfPermission()) {
                    permissionGranted = true
                    return PermissionState.GRANTED
                }
            } catch (_: Throwable) {
                // Fall through to explicit Shizuku requestPermission dialog.
            }
        }
        val code = nextRequestCode.incrementAndGet()
        val latch = CountDownLatch(1)
        pendingPermissionCode = code
        pendingPermissionAllowed = false
        permissionLatch = latch
        try {
            svc.requestPermission(code)
        } catch (_: Throwable) {
            permissionLatch = null
            return PermissionState.UNAVAILABLE
        }
        val completed = try {
            latch.await(timeoutMillis.coerceIn(1_000L, 45_000L), TimeUnit.MILLISECONDS)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } finally {
            permissionLatch = null
        }
        if (!completed) {
            return try {
                if (svc.checkSelfPermission()) {
                    permissionGranted = true
                    PermissionState.GRANTED
                } else {
                    PermissionState.TIMEOUT
                }
            } catch (_: Throwable) {
                PermissionState.TIMEOUT
            }
        }
        return if (pendingPermissionAllowed) {
            permissionGranted = true
            PermissionState.GRANTED
        } else {
            PermissionState.DENIED
        }
    }

    /** Executes one strictly allowlisted Level-2 command over the Shizuku bridge. */
    internal fun executeAllowlisted(
        context: Context,
        command: TitanShellCommand,
        workingDirectory: File,
        timeoutMillis: Long,
        maxBytes: Int,
    ): TitanBoundedProcess.Outcome {
        if (!command.allowsShizuku || command.program !in TitanShizukuUserService.ALLOWED_SHIZUKU_PROGRAMS) {
            return TitanBoundedProcess.Outcome.NOT_STARTED
        }
        if (!tryDiscoverBinder(context)) return TitanBoundedProcess.Outcome.NOT_STARTED
        val svc = synchronized(lock) { service } ?: return TitanBoundedProcess.Outcome.NOT_STARTED
        val hasPerm = try {
            permissionGranted || svc.checkSelfPermission()
        } catch (_: Throwable) {
            false
        }
        if (!hasPerm) return TitanBoundedProcess.Outcome.NOT_STARTED

        val bridge = ensureUserService(context, svc)
        if (bridge != null) {
            val outcome = runViaUserService(bridge, command, timeoutMillis, maxBytes)
            if (outcome != null) return outcome
        }
        return runViaNewProcess(svc, command, workingDirectory, timeoutMillis, maxBytes)
    }

    private fun attachHandshake(targetBinder: IBinder, packageName: String) {
        val svc = synchronized(lock) { service } ?: return
        val latch = CountDownLatch(1)
        bindLatch = latch
        try {
            val args = Bundle().apply {
                putInt(KEY_ATTACH_API_VERSION, SHIZUKU_API_VERSION)
                putString(KEY_ATTACH_PACKAGE_NAME, packageName)
            }
            svc.attachApplication(applicationStub, args)
            latch.await(ATTACH_WAIT_MS, TimeUnit.MILLISECONDS)
        } catch (_: Throwable) {
            // Older servers may pre-date v13 args; best-effort state check follows below.
            try {
                if (targetBinder.pingBinder() && svc.checkSelfPermission()) {
                    permissionGranted = true
                    attached = true
                }
            } catch (_: Throwable) {
                // Ignore; channel remains unconfirmed until probe succeeds.
            }
        } finally {
            bindLatch = null
        }
    }

    private fun ensureUserService(context: Context, svc: IShizukuService): ITitanShizukuBridge? {
        val existing = synchronized(lock) { userBridge }
        if (existing != null && existing.asBinder().pingBinder()) return existing
        if (serverApiVersion in 1..11) return null

        val latch = CountDownLatch(1)
        userServiceLatch = latch
        val conn = object : IShizukuServiceConnection.Stub() {
            override fun connected(service: IBinder?) {
                if (service != null && service.pingBinder()) {
                    synchronized(lock) {
                        userBridge = ITitanShizukuBridge.Stub.asInterface(service)
                    }
                }
                userServiceLatch?.countDown()
            }

            override fun died() {
                synchronized(lock) { userBridge = null }
            }
        }
        synchronized(lock) { userServiceConnection = conn }
        val args = Bundle().apply {
            putParcelable(
                USER_SERVICE_ARG_COMPONENT,
                ComponentName(context.packageName, TitanShizukuUserService::class.java.name),
            )
            putBoolean(USER_SERVICE_ARG_DEBUGGABLE, BuildConfig.DEBUG)
            putInt(USER_SERVICE_ARG_VERSION_CODE, BuildConfig.VERSION_CODE)
            putBoolean(USER_SERVICE_ARG_DAEMON, false)
            putBoolean(USER_SERVICE_ARG_USE_32_BIT, false)
            putString(USER_SERVICE_ARG_PROCESS_NAME, "${context.packageName}:titan_shizuku")
            putString(USER_SERVICE_ARG_TAG, USER_SERVICE_TAG)
        }
        return try {
            svc.addUserService(conn, args)
            latch.await(USER_SERVICE_BIND_WAIT_MS, TimeUnit.MILLISECONDS)
            synchronized(lock) { userBridge }
        } catch (_: Throwable) {
            null
        } finally {
            userServiceLatch = null
        }
    }

    private fun runViaUserService(
        bridge: ITitanShizukuBridge,
        command: TitanShellCommand,
        timeoutMillis: Long,
        maxBytes: Int,
    ): TitanBoundedProcess.Outcome? {
        return try {
            val bundle = bridge.runAllowlisted(
                command.program,
                command.arguments.toTypedArray(),
                timeoutMillis,
                maxBytes,
            ) ?: return null
            TitanBoundedProcess.Outcome(
                started = bundle.getBoolean(TitanShizukuUserService.KEY_STARTED, false),
                exitCode = bundle.getInt(TitanShizukuUserService.KEY_EXIT_CODE, -1),
                timedOut = bundle.getBoolean(TitanShizukuUserService.KEY_TIMED_OUT, false),
                truncated = bundle.getBoolean(TitanShizukuUserService.KEY_TRUNCATED, false),
                output = bundle.getString(TitanShizukuUserService.KEY_OUTPUT, ""),
            )
        } catch (_: Throwable) {
            synchronized(lock) { userBridge = null }
            null
        }
    }

    private fun runViaNewProcess(
        svc: IShizukuService,
        command: TitanShellCommand,
        workingDirectory: File,
        timeoutMillis: Long,
        maxBytes: Int,
    ): TitanBoundedProcess.Outcome {
        val cmd = Array(1 + command.arguments.size) { index ->
            if (index == 0) command.program else command.arguments[index - 1]
        }
        val remote: IRemoteProcess = try {
            svc.newProcess(cmd, null, workingDirectory.absolutePath)
                ?: return TitanBoundedProcess.Outcome.NOT_STARTED
        } catch (_: Throwable) {
            return TitanBoundedProcess.Outcome.NOT_STARTED
        }
        val cap = maxBytes.coerceIn(512, 512 * 1024)
        val timeout = timeoutMillis.coerceIn(250L, 30_000L)
        val captured = ByteArrayOutputStream(4096)
        val truncated = AtomicBoolean(false)
        val stdoutFd = try {
            remote.inputStream
        } catch (_: Throwable) {
            null
        }
        val stderrFd = try {
            remote.errorStream
        } catch (_: Throwable) {
            null
        }
        val outThread = stdoutFd?.let { pfd ->
            Thread({ drainPfd(pfd, cap, captured, truncated) }, "gedefense-shizuku-np-out").apply {
                isDaemon = true
                start()
            }
        }
        val errThread = stderrFd?.let { pfd ->
            Thread({ drainPfd(pfd, cap, captured, truncated) }, "gedefense-shizuku-np-err").apply {
                isDaemon = true
                start()
            }
        }
        val finished = try {
            remote.waitForTimeout(timeout, "MILLISECONDS")
        } catch (_: Throwable) {
            false
        }
        if (!finished) {
            try {
                remote.destroy()
            } catch (_: Throwable) {
                // Ignore.
            }
            joinQuietly(outThread, 200L)
            joinQuietly(errThread, 200L)
            return TitanBoundedProcess.Outcome(
                started = true,
                exitCode = -2,
                timedOut = true,
                truncated = truncated.get(),
                output = synchronized(captured) { String(captured.toByteArray(), Charsets.UTF_8) },
            )
        }
        joinQuietly(outThread, 2_000L)
        joinQuietly(errThread, 500L)
        val exitCode = try {
            remote.exitValue()
        } catch (_: Throwable) {
            -1
        }
        return TitanBoundedProcess.Outcome(
            started = true,
            exitCode = exitCode,
            timedOut = false,
            truncated = truncated.get(),
            output = synchronized(captured) { String(captured.toByteArray(), Charsets.UTF_8) },
        )
    }

    private fun drainPfd(
        pfd: ParcelFileDescriptor,
        cap: Int,
        sink: ByteArrayOutputStream,
        truncated: AtomicBoolean,
    ) {
        val stream: InputStream = ParcelFileDescriptor.AutoCloseInputStream(pfd)
        val buffer = ByteArray(4096)
        stream.use { input ->
            try {
                while (!Thread.currentThread().isInterrupted) {
                    val read = input.read(buffer)
                    if (read < 0) return
                    if (read == 0) continue
                    synchronized(sink) {
                        val remaining = cap - sink.size()
                        if (remaining > 0) sink.write(buffer, 0, minOf(remaining, read))
                        if (read > remaining) truncated.set(true)
                    }
                }
            } catch (_: Throwable) {
                // Stream closed.
            }
        }
    }

    private fun lookupViaServiceManager(): IBinder? = try {
        val smClass = Class.forName(SERVICE_MANAGER_CLASS)
        val getService = smClass.getMethod(GET_SERVICE_METHOD, String::class.java)
        getService.invoke(null, SHIZUKU_SERVICE_NAME) as? IBinder
    } catch (_: Throwable) {
        null
    }

    private fun clearState(notifyListeners: Boolean) {
        synchronized(lock) { clearLocked() }
        if (notifyListeners) {
            for (listener in deathListeners) {
                try {
                    listener()
                } catch (_: Throwable) {
                    // Isolated listener failure.
                }
            }
        }
    }

    private fun clearLocked() {
        val old = binder
        if (old != null) {
            try {
                old.unlinkToDeath(deathRecipient, 0)
            } catch (_: Throwable) {
                // Already unlinked.
            }
        }
        binder = null
        service = null
        attached = false
        permissionGranted = false
        serverUid = -1
        serverApiVersion = -1
        userBridge = null
        userServiceConnection = null
    }

    private fun joinQuietly(thread: Thread?, millis: Long) {
        if (thread == null) return
        try {
            thread.join(millis)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
        }
    }

    private const val TAG = "GeDefenseTvShizuku"
    private const val SHIZUKU_API_VERSION = 13
    private const val SHIZUKU_PERMISSION = "moe.shizuku.manager.permission.API_V23"
    private const val SERVICE_MANAGER_CLASS = "android.os.ServiceManager"
    private const val GET_SERVICE_METHOD = "getService"
    private const val SHIZUKU_SERVICE_NAME = "shizuku"
    private const val USER_SERVICE_TAG = "titan-shizuku-bridge"

    private const val KEY_ATTACH_PACKAGE_NAME = "shizuku:attach-package-name"
    private const val KEY_ATTACH_API_VERSION = "shizuku:attach-api-version"
    private const val KEY_REPLY_VERSION = "shizuku:attach-reply-version"
    private const val KEY_REPLY_UID = "shizuku:attach-reply-uid"
    private const val KEY_REPLY_PERMISSION_GRANTED = "shizuku:attach-reply-permission-granted"
    private const val KEY_PERMISSION_ALLOWED = "shizuku:request-permission-reply-allowed"

    private const val USER_SERVICE_ARG_TAG = "shizuku:user-service-arg-tag"
    private const val USER_SERVICE_ARG_COMPONENT = "shizuku:user-service-arg-component"
    private const val USER_SERVICE_ARG_DEBUGGABLE = "shizuku:user-service-arg-debuggable"
    private const val USER_SERVICE_ARG_VERSION_CODE = "shizuku:user-service-arg-version-code"
    private const val USER_SERVICE_ARG_PROCESS_NAME = "shizuku:user-service-arg-process-name"
    private const val USER_SERVICE_ARG_DAEMON = "shizuku:user-service-arg-daemon"
    private const val USER_SERVICE_ARG_USE_32_BIT = "shizuku:user-service-arg-use-32-bit-app-process"

    private const val ATTACH_WAIT_MS = 2_500L
    private const val USER_SERVICE_BIND_WAIT_MS = 3_500L
    private const val PERMISSION_WAIT_MS = 25_000L
}
