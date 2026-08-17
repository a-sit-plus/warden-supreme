package at.asitplus.warden.collector

import android.content.Context
import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import androidx.compose.ui.platform.LocalContext

@Composable
actual fun rememberEndpointStore(): EndpointStore {
    val context = LocalContext.current
    return remember(context) {
        val prefs = context.getSharedPreferences("collector", Context.MODE_PRIVATE)
        object : EndpointStore {
            override fun get(): String? = prefs.getString("endpoint", null)
            override fun set(value: String) {
                prefs.edit().putString("endpoint", value).apply()
            }
        }
    }
}
