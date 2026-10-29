package de.visiongaia.gedefense.tv.data

import android.app.Activity
import android.app.Fragment
import android.app.FragmentManager
import android.annotation.TargetApi
import android.content.ActivityNotFoundException
import android.content.ContentValues
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.provider.MediaStore
import android.util.Log
import de.visiongaia.gedefense.tv.contract.EvidenceApi
import de.visiongaia.gedefense.tv.contract.ExportResult
import de.visiongaia.gedefense.tv.contract.ReportApi
import de.visiongaia.gedefense.tv.contract.ThreatIntelApi
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.ScanResult
import de.visiongaia.gedefense.tv.core.model.SecurityReport
import de.visiongaia.gedefense.tv.core.model.TextCatalog
import de.visiongaia.gedefense.tv.core.report.ReportRenderer
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.OutputStreamWriter
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean

/** Creates the SAF "save as" intent shared by the handler probe and the picker fragment. */
private fun createReportDocumentIntent(mimeType: String, suggestedName: String): Intent =
    Intent(Intent.ACTION_CREATE_DOCUMENT)
        .addCategory(Intent.CATEGORY_OPENABLE)
        .setType(mimeType)
        .putExtra(Intent.EXTRA_TITLE, suggestedName)

/**
 * Builds and exports the local security report.
 *
 * Primary path: Storage Access Framework ([Intent.ACTION_CREATE_DOCUMENT]) with one document per
 * format (plain text + JSON), because a single SAF document cannot carry two MIME types. The picker
 * result is received by a headless [Fragment] so [ReportApi] stays a plain Activity-based contract
 * without a Lead-owned Activity callback; plain `Activity.onActivityResult` dispatches to attached
 * fragments.
 *
 * TV reality check: many Android TV / Google TV images ship without DocumentsUI, so
 * [Intent.ACTION_CREATE_DOCUMENT] has no handler — or resolves to a framework "DocumentsStub" that
 * never shows a picker. When the handler probe fails (missing handler, disabled app, or platform stub)
 * or the picker throws [ActivityNotFoundException], the exporter falls back to writing both artifacts
 * itself:
 *  - API 29+: public Downloads collection via MediaStore (`Downloads/GeDefenseTV`), no storage
 *    permission required;
 *  - API 26-28: app-specific external documents directory
 *    (`getExternalFilesDir(DIRECTORY_DOCUMENTS)/GeDefenseTV`), also permission-free.
 * Files are named `GeDefense-TV-Report-<yyyyMMdd-HHmmss>.txt` / `.json` (UTC) and the listener is
 * invoked asynchronously on the main thread exactly like the SAF path.
 */
@Suppress("DEPRECATION")
class TvReportExporter(
    context: Context,
    private val catalog: TextCatalog,
    private val renderer: ReportRenderer,
    private val evidence: EvidenceApi,
    private val threatIntel: ThreatIntelApi,
    private val deviceId: String,
) : ReportApi {
    private val appContext = context.applicationContext
    private val mainHandler = Handler(Looper.getMainLooper())
    private val fallbackExecutor = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, "gedefense-tv-report-export").apply { isDaemon = true }
    }

    override fun build(result: ScanResult): SecurityReport = SecurityReport(
        reportId = UUID.randomUUID().toString(),
        generatedAtMillis = System.currentTimeMillis(),
        deviceId = deviceId,
        scan = result,
        evidence = evidence.health(),
        threatIntel = threatIntel.status(),
    )

    override fun export(
        report: SecurityReport,
        activity: Activity,
        listener: (ExportResult) -> Unit,
    ): Boolean {
        if (activity.isFinishing) return false
        val text = try {
            renderer.renderText(report, catalog)
        } catch (_: Throwable) {
            return false
        }
        val json = try {
            renderer.renderJson(report)
        } catch (_: Throwable) {
            return false
        }
        if (text.length > MAX_EXPORT_CHARS || json.length > MAX_EXPORT_CHARS) return false
        val baseName = "GeDefense-TV-Report-${timestampSuffix()}"

        val hasPicker = hasDocumentPicker(activity)
        if (!hasPicker) {
            Log.w(TAG, "no SAF document picker handler; using permission-free Downloads fallback")
            startFallbackExport(text, json, baseName, fragment = null, listener = listener)
            return true
        }

        val fragmentManager: FragmentManager = activity.fragmentManager
        if (fragmentManager.findFragmentByTag(TAG) != null) return false
        val fragment = TvReportExportFragment().apply {
            this.listener = listener
            renderText = text
            renderJson = json
            fileNameBase = baseName
        }
        fragment.pickerUnavailable = {
            Log.w(TAG, "SAF picker unavailable at start time; using fallback export")
            startFallbackExport(text, json, baseName, fragment = fragment, listener = listener)
        }
        return try {
            fragmentManager.beginTransaction().add(fragment, TAG).commitAllowingStateLoss()
            true
        } catch (_: Throwable) {
            fragment.skipListener()
            false
        }
    }

    private fun hasDocumentPicker(activity: Activity): Boolean = try {
        val resolved = createReportDocumentIntent("text/plain", "probe.txt")
            .resolveActivity(activity.packageManager)
        if (resolved == null) {
            false
        } else {
            val packageName = resolved.packageName.orEmpty()
            val className = resolved.className.orEmpty()
            val enabled = try {
                activity.packageManager.getPackageInfo(packageName, 0).applicationInfo?.enabled ?: true
            } catch (_: Throwable) {
                true
            }
            if (!enabled) {
                false
            } else if (isStubPicker(packageName, className)) {
                // Android TV images resolve the SAF intent to a framework DocumentsStub that never
                // shows a picker and finishes with RESULT_CANCELED. Resolution alone is therefore not
                // proof of a usable picker; such stubs are treated as "no handler" so the export
                // still produces real artifacts instead of a silent cancel.
                Log.w(TAG, "SAF intent resolves to a platform stub picker ($packageName/$className); using fallback")
                false
            } else {
                true
            }
        }
    } catch (_: Throwable) {
        false
    }

    private fun isStubPicker(packageName: String, className: String): Boolean {
        val lowerPackage = packageName.lowercase(Locale.US)
        val lowerClass = className.lowercase(Locale.US)
        return lowerPackage.contains("frameworkpackagestubs") ||
            lowerPackage.contains("stub") ||
            lowerClass.contains("stub")
    }

    /**
     * Writes both report formats without a document picker. Runs on a dedicated background thread and
     * reports through the main thread, matching the asynchronous SAF contract.
     */
    private fun startFallbackExport(
        text: String,
        json: String,
        baseName: String,
        fragment: TvReportExportFragment?,
        listener: (ExportResult) -> Unit,
    ) {
        fallbackExecutor.execute {
            val result = try {
                writeFallback("$baseName.txt", text, "text/plain")
                writeFallback("$baseName.json", json, "application/json")
                ExportResult(ok = true, fileName = "$baseName.json (+ .txt)", message = MessageRef(KEY_EXPORT_OK))
            } catch (error: Throwable) {
                Log.w(TAG, "fallback report export failed: ${describe(error)}")
                ExportResult(ok = false, fileName = null, message = MessageRef(KEY_EXPORT_FAILED))
            }
            mainHandler.post {
                try {
                    if (fragment != null) {
                        fragment.complete(result)
                    } else {
                        listener(result)
                    }
                } catch (_: Throwable) {
                    // A UI callback must never crash the export host.
                }
            }
        }
    }

    private fun writeFallback(displayName: String, content: String, mimeType: String) {
        if (Build.VERSION.SDK_INT >= 29) {
            writeToMediaStoreDownloads(displayName, content, mimeType)
        } else {
            writeToAppDocuments(displayName, content)
        }
    }

    @TargetApi(29)
    private fun writeToMediaStoreDownloads(displayName: String, content: String, mimeType: String) {
        val resolver = appContext.contentResolver
        val values = ContentValues().apply {
            put(MediaStore.MediaColumns.DISPLAY_NAME, displayName)
            put(MediaStore.MediaColumns.MIME_TYPE, mimeType)
            put(MediaStore.MediaColumns.RELATIVE_PATH, "${Environment.DIRECTORY_DOWNLOADS}/$EXPORT_DIRECTORY")
            put(MediaStore.MediaColumns.IS_PENDING, 1)
        }
        val uri: Uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, values)
            ?: throw IOException("MediaStore insert failed")
        try {
            val output = resolver.openOutputStream(uri, "w") ?: throw IOException("MediaStore open failed")
            OutputStreamWriter(output, Charsets.UTF_8).use { writer ->
                writer.write(content)
                writer.flush()
            }
            val ready = ContentValues().apply { put(MediaStore.MediaColumns.IS_PENDING, 0) }
            resolver.update(uri, ready, null, null)
        } catch (error: Throwable) {
            runCatching { resolver.delete(uri, null, null) }
            throw error
        }
    }

    private fun writeToAppDocuments(displayName: String, content: String) {
        val documents = appContext.getExternalFilesDir(Environment.DIRECTORY_DOCUMENTS) ?: appContext.filesDir
        val directory = File(documents, EXPORT_DIRECTORY)
        if (!directory.mkdirs() && !directory.isDirectory) throw IOException("export directory unavailable")
        val file = File(directory, displayName)
        FileOutputStream(file, false).use { output ->
            OutputStreamWriter(output, Charsets.UTF_8).use { writer ->
                writer.write(content)
                writer.flush()
            }
        }
    }

    private fun timestampSuffix(): String =
        SimpleDateFormat("yyyyMMdd-HHmmss", Locale.US).apply {
            timeZone = TimeZone.getTimeZone("UTC")
        }.format(Date())

    private fun describe(error: Throwable): String {
        val message = error.message.orEmpty()
            .map { character -> if (character == '\n' || character == '\r') ' ' else character }
            .joinToString("")
            .trim()
            .take(120)
        return "${error::class.java.simpleName}: $message"
    }

    /** Headless SAF document-picker host; receives its own onActivityResult from the Activity. */
    @Suppress("DEPRECATION")
    class TvReportExportFragment : Fragment() {
        var listener: ((ExportResult) -> Unit)? = null
        var renderText: String = ""
        var renderJson: String = ""
        var fileNameBase: String = ""

        /** Invoked when the SAF picker cannot be started (no DocumentsUI on this TV image). */
        var pickerUnavailable: (() -> Unit)? = null

        private var stage = STAGE_TEXT
        private var finished = false
        private val finishedGuard = AtomicBoolean(false)

        init {
            retainInstance = true
        }

        override fun onCreate(savedInstanceState: Bundle?) {
            super.onCreate(savedInstanceState)
            if (savedInstanceState != null) {
                // After a process death the rendered payload is gone; fail closed instead of
                // exporting a truncated or empty document.
                if (renderText.isEmpty() && renderJson.isEmpty()) {
                    finishWith(ExportResult(false, null, MessageRef(KEY_EXPORT_FAILED)))
                    return
                }
                stage = savedInstanceState.getInt(KEY_STAGE, STAGE_TEXT)
            }
        }

        override fun onStart() {
            super.onStart()
            if (finished || stage != STAGE_TEXT || hasStartedPicker) return
            startTextPicker()
        }

        override fun onSaveInstanceState(outState: Bundle) {
            super.onSaveInstanceState(outState)
            outState.putInt(KEY_STAGE, stage)
        }

        override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
            super.onActivityResult(requestCode, resultCode, data)
            if (finished) return
            when (requestCode) {
                REQUEST_TEXT -> {
                    if (resultCode != Activity.RESULT_OK || data?.data == null) {
                        finishWith(ExportResult(false, null, MessageRef(KEY_EXPORT_CANCELLED)))
                        return
                    }
                    if (!writeDocument(data.data!!, renderText)) {
                        finishWith(ExportResult(false, null, MessageRef(KEY_EXPORT_FAILED)))
                        return
                    }
                    stage = STAGE_JSON
                    startJsonPicker()
                }
                REQUEST_JSON -> {
                    if (resultCode != Activity.RESULT_OK || data?.data == null) {
                        finishWith(ExportResult(true, "$fileNameBase.txt", MessageRef(KEY_EXPORT_PARTIAL)))
                        return
                    }
                    if (!writeDocument(data.data!!, renderJson)) {
                        finishWith(ExportResult(false, "$fileNameBase.txt", MessageRef(KEY_EXPORT_FAILED)))
                        return
                    }
                    finishWith(ExportResult(true, "$fileNameBase.txt", MessageRef(KEY_EXPORT_OK)))
                }
                else -> Unit
            }
        }

        fun skipListener() {
            listener = null
        }

        /** Delivers the fallback result through the same single-shot completion path as the SAF path. */
        fun complete(result: ExportResult) {
            finishWith(result)
        }

        private var hasStartedPicker = false

        private fun startTextPicker() {
            hasStartedPicker = true
            try {
                startActivityForResult(
                    createReportDocumentIntent("text/plain", "$fileNameBase.txt"),
                    REQUEST_TEXT,
                )
            } catch (error: Throwable) {
                handlePickerFailure(error)
            }
        }

        private fun startJsonPicker() {
            try {
                startActivityForResult(
                    createReportDocumentIntent("application/json", "$fileNameBase.json"),
                    REQUEST_JSON,
                )
            } catch (error: Throwable) {
                handlePickerFailure(error)
            }
        }

        private fun handlePickerFailure(error: Throwable) {
            val fallback = pickerUnavailable
            if (error is ActivityNotFoundException && fallback != null) {
                pickerUnavailable = null
                fallback()
                return
            }
            Log.w("GeDefenseTvReport", "SAF picker failed: ${error::class.java.simpleName}")
            finishWith(ExportResult(false, null, MessageRef(KEY_EXPORT_UNAVAILABLE)))
        }

        private fun writeDocument(uri: Uri, content: String): Boolean {
            val resolver = activity?.contentResolver ?: return false
            return try {
                val output = resolver.openOutputStream(uri, "wt") ?: return false
                OutputStreamWriter(output, Charsets.UTF_8).use { writer ->
                    writer.write(content)
                    writer.flush()
                }
                true
            } catch (_: Throwable) {
                false
            }
        }

        private fun finishWith(result: ExportResult) {
            if (!finishedGuard.compareAndSet(false, true)) return
            finished = true
            val callback = listener
            listener = null
            activity?.fragmentManager?.let { manager ->
                try {
                    manager.beginTransaction().remove(this).commitAllowingStateLoss()
                } catch (_: Throwable) {
                    // The fragment is retained memory only; failing to remove it must not hide the result.
                }
            }
            try {
                callback?.invoke(result)
            } catch (_: Throwable) {
                // A UI callback must never crash the export host.
            }
        }

        companion object {
            private const val REQUEST_TEXT = 7301
            private const val REQUEST_JSON = 7302
            private const val STAGE_TEXT = 0
            private const val STAGE_JSON = 1
            private const val KEY_STAGE = "stage"
            private val KEY_EXPORT_OK = "export.ok"
            private val KEY_EXPORT_PARTIAL = "export.partial"
            private val KEY_EXPORT_CANCELLED = "export.cancelled"
            private val KEY_EXPORT_FAILED = "export.failed"
            private val KEY_EXPORT_UNAVAILABLE = "export.unavailable"
        }
    }

    companion object {
        private const val TAG = "gedefense-tv-report-export"
        private const val MAX_EXPORT_CHARS = 2_000_000
        private const val EXPORT_DIRECTORY = "GeDefenseTV"
        private val KEY_EXPORT_OK = "export.ok"
        private val KEY_EXPORT_FAILED = "export.failed"
    }
}
