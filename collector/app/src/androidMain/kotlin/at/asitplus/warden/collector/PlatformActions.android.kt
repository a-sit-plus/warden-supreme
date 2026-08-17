package at.asitplus.warden.collector

import android.content.Intent
import android.net.Uri
import android.widget.Toast
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

@Composable
actual fun rememberPlatformActions(): PlatformActions {
    val context = LocalContext.current
    return remember(context) {
        object : PlatformActions {
            override fun toast(message: String) {
                Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
            }

            override fun openUrl(url: String) {
                context.startActivity(
                    Intent(Intent.ACTION_VIEW, Uri.parse(url)).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                )
            }
        }
    }
}
