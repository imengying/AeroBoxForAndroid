package com.aerobox.core.errors

import android.content.Context
import androidx.annotation.StringRes

/**
 * Exception whose message is sourced from a Resources string ID, so that the
 * UI layer can render it in the user's locale instead of being stuck with
 * whatever language the throw site happened to be written in.
 *
 * Throw sites in the core and data layers should never embed a hard-coded
 * locale-bound message; they should pick a `R.string.error_*` resource and
 * pass it (with arguments) through this class. ViewModels can call
 * [resolveMessage] (or the [localizedMessageOrFallback] extension) to render
 * the message in the active locale.
 */
class LocalizedException(
    @StringRes val messageResId: Int,
    val formatArgs: List<Any?> = emptyList(),
    cause: Throwable? = null
) : RuntimeException(messageResId.toString(), cause) {

    /** Resolve the localized message lazily against the supplied [context]. */
    fun resolveMessage(context: Context): String {
        return if (formatArgs.isEmpty()) {
            context.getString(messageResId)
        } else {
            context.getString(messageResId, *formatArgs.toTypedArray())
        }
    }

    companion object {
        /**
         * Convenience factory. Pass zero or more format args; they are
         * substituted into the resource string at resolve time.
         */
        fun of(@StringRes resId: Int, vararg args: Any?): LocalizedException {
            return LocalizedException(resId, args.toList())
        }
    }
}

/**
 * Best-effort translator: if `this` is a [LocalizedException], render it
 * against [context]; otherwise fall back to the throwable's own message,
 * and finally to [fallback] when even that is blank.
 *
 * Useful inside ViewModels that already have a Throwable in hand.
 */
fun Throwable.localizedMessageOrFallback(context: Context, fallback: String): String {
    return when (this) {
        is LocalizedException -> resolveMessage(context)
        else -> message?.takeIf { it.isNotBlank() } ?: fallback
    }
}
