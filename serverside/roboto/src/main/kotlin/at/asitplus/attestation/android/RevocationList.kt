package at.asitplus.attestation.android

import io.ktor.client.HttpClient
import io.ktor.client.HttpClientConfig
import io.ktor.client.call.body
import io.ktor.client.engine.ProxyBuilder
import io.ktor.client.engine.cio.CIO
import io.ktor.client.engine.http
import io.ktor.client.plugins.cache.HttpCache
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.client.request.get
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.ExperimentalSerializationApi
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.json.jsonObject
import java.io.IOException
import java.io.InputStream
import java.math.BigInteger
import java.util.Locale

class RevocationList(json: JsonObject) {
    private val entries by lazy { json["entries"]?.jsonObject ?: throw IOException() }
    fun isRevoked(
        serialNumber: BigInteger
    ): Boolean {
        val serialNumberNormalised = serialNumber.toString(16).lowercase(Locale.getDefault())
        return entries[serialNumberNormalised] != null //any entry is a red flag!
    }

    companion object {
        @JvmStatic
        private val client by lazy { HttpClient(CIO) { setup(null) } }

        @OptIn(ExperimentalSerializationApi::class)
        @JvmStatic
        fun from(source: InputStream) = RevocationList(json.decodeFromStream(source))

        @Throws(Throwable::class)
        @JvmStatic
        @JvmOverloads
        fun fromGoogleServer(client: HttpClient = this.client) =
            runBlocking {
                RevocationList(client.get("https://android.googleapis.com/attestation/status").body<JsonObject>())
            }
    }
}


fun HttpClientConfig<*>.setup(proxyUrl: String?) =
    apply {
        install(HttpCache)
        install(ContentNegotiation) { json(json) }
        engine { proxyUrl?.let { proxy = ProxyBuilder.http(it) } }
    }
