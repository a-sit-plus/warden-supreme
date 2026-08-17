package at.asitplus.warden.collector

import androidx.compose.runtime.Composable

/** Tiny persistent store for the backend URL, so it survives app restarts. */
interface EndpointStore {
    fun get(): String?
    fun set(value: String)
}

@Composable
expect fun rememberEndpointStore(): EndpointStore
