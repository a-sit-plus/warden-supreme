package at.asitplus.warden.collector

import androidx.compose.runtime.Composable

/** Platform integrations that have no common Compose equivalent. */
interface PlatformActions {
    /** Version code of the installed app, or a sentinel on platforms without Android packages. */
    val appVersionCode: Long

    /** Shows a short, transient message (a real Toast on Android; no-op where unsupported). */
    fun toast(message: String)

    /** Opens [url] in the system browser. */
    fun openUrl(url: String)
}

@Composable
expect fun rememberPlatformActions(): PlatformActions
