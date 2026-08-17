package at.asitplus.warden.collector

import android.content.Context
import android.content.pm.PackageManager
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

@Composable
actual fun rememberEndpointStore(): EndpointStore {
    val context = LocalContext.current
    return remember(context) {
        val prefs = context.getSharedPreferences("collector", Context.MODE_PRIVATE)
        val defaultEndpoint = context.packageManager.getApplicationInfo(
            context.packageName,
            PackageManager.GET_META_DATA,
        ).metaData?.getString("at.asitplus.warden.collector.BASE_URL")
            ?: "https://attestation-collector.sliplane.app"
        object : EndpointStore {
            override val defaultEndpoint: String = defaultEndpoint
            override fun get(): String? = prefs.getString("endpoint", null)
            override fun set(value: String) {
                prefs.edit().putString("endpoint", value).apply()
            }
        }
    }
}
