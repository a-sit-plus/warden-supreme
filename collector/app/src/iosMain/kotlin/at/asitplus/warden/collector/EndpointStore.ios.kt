package at.asitplus.warden.collector

import androidx.compose.runtime.Composable
import androidx.compose.runtime.remember
import platform.Foundation.NSUserDefaults

@Composable
actual fun rememberEndpointStore(): EndpointStore = remember {
    val defaults = NSUserDefaults.standardUserDefaults
    object : EndpointStore {
        override val defaultEndpoint: String = "https://attestation-collector.sliplane.app"
        override fun get(): String? = defaults.stringForKey("endpoint")
        override fun set(value: String) = defaults.setObject(value, forKey = "endpoint")
    }
}
