package at.asitplus.warden.collector

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import platform.Foundation.NSURL
import platform.UIKit.UIApplication

@Composable
actual fun rememberPlatformActions(): PlatformActions = remember {
    object : PlatformActions {
        override fun toast(message: String) {
            // iOS has no toast; the iOS target here is build-only.
        }

        override fun openUrl(url: String) {
            NSURL.URLWithString(url)?.let { UIApplication.sharedApplication.openURL(it) }
        }
    }
}
