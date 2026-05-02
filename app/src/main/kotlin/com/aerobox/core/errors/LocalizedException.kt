package com.aerobox.core.errors

import android.content.Context
import androidx.annotation.StringRes
import com.aerobox.R

/**
 * Exception whose message is sourced from a Resources string ID, so that the
 * UI layer can render it in the user's locale instead of being stuck with
 * whatever language the throw site happened to be written in.
 *
 * Throw sites in `core/*` and `data/*` should never embed a hard-coded
 * locale-bound message; they should pick a `R.string.error_*` resource and
 * pass it (with arguments) through this class. [SubscriptionViewModel]'s
 * `toFriendlyError` resolves [resolveMessage] against the app context.
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
        /** Convenience wrapper for `R.string.error_*` codes with no args. */
        fun of(@StringRes resId: Int): LocalizedException = LocalizedException(resId)

        /** Convenience wrapper for `R.string.error_*` codes with format args. */
        fun of(@StringRes resId: Int, vararg args: Any?): LocalizedException =
            LocalizedException(resId, args.toList())
    }
}

/**
 * Best-effort translator: if [error] is a [LocalizedException], render it
 * against [context]; otherwise fall back to the throwable's own message.
 *
 * Useful inside ViewModels that already have a Throwable in hand.
 */
fun Throwable.localizedMessageOrFallback(context: Context, fallback: String): String {
    return when (this) {
        is LocalizedException -> resolveMessage(context)
        else -> message?.takeIf { it.isNotBlank() } ?: fallback
    }
}

@Suppress("unused") // Reserved as a sentinel for callers that want to look up
                   // a string resource without throwing. Currently unused but
                   // kept to keep the error layer self-contained.
fun Context.errorString(@StringRes resId: Int, vararg args: Any?): String {
    return if (args.isEmpty()) getString(resId) else getString(resId, *args)
}

// Compile-time anchor so accidentally importing R.string.* outside this file
// doesn't get caught off-guard by missing resources during refactors.
@Suppress("unused")
private val ERROR_RES_ANCHOR = R.string.error_node_server_empty
