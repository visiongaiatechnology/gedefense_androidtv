package de.visiongaia.gedefense.tv.platform.titan.privilege

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.content.pm.ProviderInfo
import android.database.Cursor
import android.net.Uri
import android.os.Build
import android.os.Bundle
import moe.shizuku.api.BinderContainer

/**
 * Receives the privileged Shizuku service binder pushed over ContentProvider IPC (`sendBinder`).
 *
 * Security boundaries:
 *  - Manifest-protected by `android.permission.INTERACT_ACROSS_USERS_FULL`, which `com.android.shell`
 *    and root hold while ordinary unprivileged apps do not.
 *  - Validates `exported = true` and `multiprocess = false` at attach time.
 *  - Accepts only `sendBinder` and internal same-process `getBinder`; never stores credentials.
 */
class TitanShizukuProvider : ContentProvider() {

    override fun attachInfo(context: Context, info: ProviderInfo) {
        super.attachInfo(context, info)
        check(!info.multiprocess) { "android:multiprocess must be false" }
        check(info.exported) { "android:exported must be true" }
    }

    override fun onCreate(): Boolean = true

    override fun call(method: String, arg: String?, extras: Bundle?): Bundle? {
        return when (method) {
            METHOD_SEND_BINDER -> {
                if (extras == null) return null
                extras.classLoader = BinderContainer::class.java.classLoader
                val container = extractContainer(extras)
                val binder = container?.binder
                val ctx = context
                if (binder != null && ctx != null) {
                    TitanShizukuClient.onBinderReceived(binder, ctx.packageName)
                }
                Bundle()
            }

            METHOD_GET_BINDER -> {
                val binder = TitanShizukuClient.currentBinder() ?: return null
                Bundle().apply {
                    putParcelable(EXTRA_BINDER, BinderContainer(binder))
                }
            }

            else -> null
        }
    }

    @Suppress("DEPRECATION")
    private fun extractContainer(extras: Bundle): BinderContainer? = try {
        if (Build.VERSION.SDK_INT >= 33) {
            extras.getParcelable(EXTRA_BINDER, BinderContainer::class.java)
        } else {
            extras.getParcelable(EXTRA_BINDER)
        }
    } catch (_: Throwable) {
        null
    }

    override fun query(
        uri: Uri,
        projection: Array<out String>?,
        selection: String?,
        selectionArgs: Array<out String>?,
        sortOrder: String?,
    ): Cursor? = null

    override fun getType(uri: Uri): String? = null

    override fun insert(uri: Uri, values: ContentValues?): Uri? = null

    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = 0

    override fun update(
        uri: Uri,
        values: ContentValues?,
        selection: String?,
        selectionArgs: Array<out String>?,
    ): Int = 0

    companion object {
        const val METHOD_SEND_BINDER = "sendBinder"
        const val METHOD_GET_BINDER = "getBinder"
        const val EXTRA_BINDER = "moe.shizuku.privileged.api.intent.extra.BINDER"
    }
}
