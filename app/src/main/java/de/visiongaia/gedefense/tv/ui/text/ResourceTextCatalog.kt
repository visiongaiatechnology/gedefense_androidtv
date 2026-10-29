package de.visiongaia.gedefense.tv.ui.text

import android.content.Context
import de.visiongaia.gedefense.tv.core.model.MessageRef
import de.visiongaia.gedefense.tv.core.model.TextCatalog
import de.visiongaia.gedefense.tv.core.text.DeCatalog

/**
 * Locale-aware catalog for all user-facing domain messages (findings, XDR, evidence, report).
 *
 * The stable [MessageRef] keys map to localized Android string resources, so the message layer
 * follows the same TV locale as the rest of the UI. The German [DeCatalog] remains the last-resort
 * fallback for keys that have no resource entry yet; it is never used for a known translated key.
 */
class ResourceTextCatalog(private val context: Context) : TextCatalog {

    override fun resolve(ref: MessageRef): String {
        val resourceId = CatalogResources.ids[ref.key]
        val template = if (resourceId != null) {
            try {
                context.getString(resourceId)
            } catch (_: RuntimeException) {
                DeCatalog.resolve(ref)
            }
        } else {
            DeCatalog.resolve(ref)
        }
        if (ref.args.isEmpty()) return template
        return ARG_PATTERN.replace(template) { match ->
            val index = match.groupValues[1].toInt()
            ref.args.getOrNull(index) ?: match.value
        }
    }

    private companion object {
        val ARG_PATTERN = Regex("[{]([0-7])[}]")
    }
}
