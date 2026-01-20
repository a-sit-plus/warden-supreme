package at.asitplus.attestation.android

import at.asitplus.attestation.android.AttestationRevocationList.HttpLoader.Configuration.ProxyConfig.Type
import at.asitplus.attestation.android.AttestationRevocationList.Loader.Configuration
import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.decodeFromJsonElement
import kotlinx.serialization.json.decodeFromStream
import kotlinx.serialization.modules.SerializersModule
import kotlinx.serialization.modules.polymorphic
import kotlinx.serialization.modules.subclass
import java.io.FileInputStream
import java.math.BigInteger
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.*
import kotlin.math.min
import kotlin.reflect.KClass
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime
import kotlin.time.Instant
import kotlin.time.toKotlinInstant


/**
 * Represents a revocation list specific to Android attestation  as per
 * [the official specification}(https://developer.android.com/privacy-and-security/security-key-attestation#certificate_status),
 * containing information about revoked or suspended certificates, metadata on expiration, and modification timestamps.
 *
 * @property entries A map where keys represent unique certificate serial numbers and values
 * correspond to revocation entries detailing the status and reason.
 * @property date The optional timestamp indicating when the revocation list was issued.
 * @property expires The optional expiration timestamp after which this list is no longer valid.
 * If `null`, the entry does not expire. See also [isExpired].
 * @property lastModified The optional timestamp indicating the last modification date of the list.
 */
@OptIn(ExperimentalTime::class)
@Serializable
data class AttestationRevocationList(
    val entries: Map<String, Entry>,
    val date: Instant? = null,
    val expires: Instant? = null,
    val lastModified: Instant? = null
) {

    fun isExpired(now: Instant): Boolean = expires?.let { now > it } ?: false
    fun isExpired(now: java.time.Instant) = isExpired(now.toKotlinInstant())

    /**
     * Represents a revocation entry containing information about the status,
     * reason for revocation, and the optional expiration date.
     *
     * @property status The revocation status of the entry, indicating if it is revoked or suspended.
     * @property reason The reason for the revocation, such as revoked or suspended.
     * @property expires The optional expiration date for the entry in ISO-8601 format.
     * Only ever present for [RevocationStatus.SUSPENDED]. If `null`, the entry does not expire.
     * See also [isExpired].
     */
    @Serializable
    data class Entry(
        val status: RevocationStatus,
        val reason: RevocationReason? = null,
        @Serializable(with = Iso8601YyyMmDdSerializer::class)
        val expires: Instant? = null,
        val comment: String? = null
    ) {
        fun isExpired(now: Instant): Boolean = expires?.let { now > it } ?: false
        fun isExpired(now: java.time.Instant) = isExpired(now.toKotlinInstant())
    }

    @Serializable
    enum class RevocationStatus {
        REVOKED,
        SUSPENDED
    }

    @Serializable
    enum class RevocationReason {
        UNSPECIFIED,
        KEY_COMPROMISE,
        CA_COMPROMISE,
        SUPERSEDED,
        SOFTWARE_FLAW
    }


    /**
     * Checks if a device with the given serial number is either revoked or suspended.
     *
     * @param serial The unique serial number of the certificate being checked.
     * @return `true` if the serial number exists in the revocation list, indicating
     *         that the device has been revoked or suspended; `false` otherwise.
     */
    fun isRevokedOrSuspended(serial: String) = entries.containsKey(serial)

    /**
     * Checks if a device with the given serial number is either revoked or suspended.
     *
     * @param serialNumber The unique serial number of the certificate being checked.
     * @return `true` if the serial number exists in the revocation list, indicating
     *         that the device has been revoked or suspended; `false` otherwise.
     */
    fun isRevokedOrSuspended(
        serialNumber: BigInteger
    ): Boolean {
        val serialNumberNormalised = serialNumber.toString(16).lowercase(Locale.getDefault())
        return entries.containsKey(serialNumberNormalised)
    }

    fun serialize() = json.encodeToString(this)


    companion object {

        private val configSubclasses = mutableSetOf<KClass<Configuration<*>>>()

        fun registerConfiguration(clazz: KClass<Configuration<*>>) {
            configSubclasses.add(clazz)
        }


        internal val json by lazy {
            Json {
                ignoreUnknownKeys = true
                isLenient = true
                encodeDefaults = false
                explicitNulls = false

                serializersModule = SerializersModule {
                    polymorphic(Configuration::class) {
                        subclass(FileLoader.Configuration::class)
                        subclass(HttpLoader.Configuration::class)
                        configSubclasses.forEach { subclass(it) }
                    }
                }
                classDiscriminator = "type"
            }
        }


        fun deserialize(
            jsonString: String,
            dateOverride: Instant? = null,
            expiresOverride: Instant? = null,
            lastModifiedOverride: Instant? = null
        ): AttestationRevocationList =
            deserialize(
                json.decodeFromString<JsonObject>(jsonString),
                dateOverride = dateOverride,
                expiresOverride = expiresOverride,
                lastModifiedOverride = lastModifiedOverride
            )

        fun deserialize(
            jsonObject: JsonObject,
            dateOverride: Instant? = null,
            expiresOverride: Instant? = null,
            lastModifiedOverride: Instant? = null
        ): AttestationRevocationList =
            json.decodeFromJsonElement<AttestationRevocationList>(jsonObject)
                .let { parsed -> dateOverride?.let { parsed.copy(date = it) } ?: parsed }
                .let { parsed -> expiresOverride?.let { parsed.copy(expires = it) } ?: parsed }
                .let { parsed -> lastModifiedOverride?.let { parsed.copy(lastModified = it) } ?: parsed }
    }

    /**
     * Generic Interface to load an [AttestationRevocationList].
     * Implementing classes are expected to be configured with any
     * parameters needed for loading, s.t. loading itself requires no parameters
     */
    interface Loader {
        val fallbackRevocationListValiditySeconds: Long

        interface Configuration<L : Loader> {
            fun createLoader(): L
            val fallbackRevocationListValiditySeconds: Long

            companion object {

            }
        }


        /**
         * Loads an [AttestationRevocationList], which provides information
         * about revoked or suspended devices as per the official specification.
         * The implementation details, such as the source of the revocation list,
         * may vary depending on the specific implementation of the `Loader` interface.
         *
         * This will only return a fresh [AttestationRevocationList] if the last loaded one is expired.
         *
         * @return The loaded `AndroidAttestationRevocationList`, containing details
         * on revoked or suspended entries, along with metadata such as expiration
         * and modification dates (when available).
         * @throws Throwable if an error occurs during the loading process, such as
         * network issues, IO errors, or invalid data.
         */
        @Throws(Throwable::class)
        suspend fun load(now: Instant): AttestationRevocationList

        /**
         * Loads an [AttestationRevocationList] in a blocking manner.
         *
         * @see load
         */
        @Throws(Throwable::class)
        fun loadBlocking(now: Instant): AttestationRevocationList = runBlocking { load(now) }
    }

    abstract class CachingLoader : Loader {
        private val cacheLock = Mutex()
        private var cachedList: AttestationRevocationList? = null

        @Throws(Throwable::class)
        override suspend fun load(now: Instant): AttestationRevocationList = cacheLock.withLock {
            cachedList?.let {
                if (it.expires == null || it.expires > now)
                    return it
            }
            fetch(now).also { cachedList = it }
        }

        abstract suspend fun fetch(now: Instant): AttestationRevocationList

    }

    /**
     * Caching HTTP [Loader] that fetches an
     * [AttestationRevocationList] over HTTP. This class uses an
     * [HttpClient] to perform requests and parses the fetched JSON content
     * into the revocation list format and respects [HttpHeaders.CacheControl]!
     *
     * @param T The type of the [HttpClientEngineConfig] to configure the HTTP engine.
     * @param engineFactory The factory responsible for creating the engine used for the HTTP client.
     * @param url The URL from which the revocation list will be fetched.
     * Defaults to the official Google attestation revocation list URL.
     * @param preferHeaderBasedExpiry if `true` (which is the default), a present [HttpHeaders.CacheControl] `max-age` property
     * will take precedence over a potentially present [HttpHeaders.Expires] value.
     * Note that Google explicitly mentions cache control to communicate expiry times. Most probably
     * because it will work as expected regardless of clock drifts.
     *
     * @param config An optional HTTP client configuration lambda that allows customization of the client's behaviour.
     * Note that fixed defaults for caching, content-negotiation, and deserialization may override parts of the provided config.
     */
    class HttpLoader<T : HttpClientEngineConfig>(
        engineFactory: HttpClientEngineFactory<T>,
        val url: String,
        override val fallbackRevocationListValiditySeconds: Long,
        private val preferHeaderBasedExpiry: Boolean = true,
        config: HttpClientConfig<T>.() -> Unit
    ) : AttestationRevocationList.CachingLoader() {

        private val httpClient = HttpClient(engineFactory) {
            config()
            install(ContentNegotiation) { json(json) }
        }

        override suspend fun fetch(now: Instant): AttestationRevocationList =
            httpClient.get(url).run {
                val validity: Duration? = if (this@HttpLoader.preferHeaderBasedExpiry) {
                    val cacheControl =
                        headers.getAll(HttpHeaders.CacheControl)
                            .orEmpty()
                            .asSequence()
                            .flatMap { it.split(',') }.filter { it.contains("=") }
                            .map { it.split("=") }.filter { it.size == 2 }.filter { it.first() == "max-age" }
                            .toList()
                    if (cacheControl.size > 1)
                        throw IllegalArgumentException("Found multiple Cache-Control entries setting a max-age: ${cacheControl.joinToString { it.joinToString() }}")
                    val cacheControlTime =
                        if (cacheControl.isNotEmpty()) cacheControl.first()[2].toLong().seconds else null
                    val expiry = headers.getInstant(HttpHeaders.Expires)?.let { it - now }
                    if (cacheControlTime == null && expiry == null) null
                    else if (cacheControlTime == null) expiry
                    else if (expiry == null) cacheControlTime
                    else min(cacheControlTime.inWholeSeconds, expiry.inWholeSeconds).seconds
                } else null

                deserialize(
                    jsonObject = body<JsonObject>(),
                    dateOverride = headers.getInstant(HttpHeaders.Date),
                    expiresOverride = (validity ?: fallbackRevocationListValiditySeconds.seconds).let { now + it },
                    lastModifiedOverride = headers.getInstant(HttpHeaders.LastModified)
                )
            }


        @Serializable
        @SerialName("http")
        data class Configuration(
            val url: String = GOOGLE_OFFICIAL_REVOCATION_LIST,
            override val fallbackRevocationListValiditySeconds: Long = 0,
            val preferHeaderBasedExpiry: Boolean = true,
            val proxyConfig: ProxyConfig? = null
        ) : Loader.Configuration<HttpLoader<HttpClientEngineConfig>> {

            override fun createLoader(): HttpLoader<HttpClientEngineConfig> =
                HttpLoader(CIO, url, fallbackRevocationListValiditySeconds, preferHeaderBasedExpiry) {
                    proxyConfig?.let { cfg ->
                        when (cfg.type) {
                            ProxyConfig.Type.SOCKS -> {
                                val hostAndPort = proxyConfig.url.split(":")
                                engine { proxy = ProxyBuilder.socks(hostAndPort.first(), hostAndPort.last().toInt()) }
                            }

                            ProxyConfig.Type.HTTP -> engine { proxy = ProxyBuilder.http(proxyConfig.url) }
                        }
                    }
                }


            @Serializable
            data class ProxyConfig(val type: Type, val url: String) {
                enum class Type {
                    SOCKS,
                    HTTP,

                }
            }

            object GoogleDefault {
                /**
                 * convenience helper to optionally set an HTTP Proxy. if [url] is `null`, no proxy will be configured.
                 */
                fun withHttpProxy(url: String?) = HttpLoader.Configuration(
                    url = GOOGLE_OFFICIAL_REVOCATION_LIST,
                    fallbackRevocationListValiditySeconds = 60 /*to prevent rate limiting*/,
                    proxyConfig = url?.let {
                        ProxyConfig(
                            type = Type.HTTP,
                            it
                        )
                    })
            }
        }

        companion object {
            private val httpDateFormatter =
                DateTimeFormatter.RFC_1123_DATE_TIME.withZone(ZoneOffset.UTC)

            private fun Headers.getInstant(name: String): Instant? =
                get(name)?.let {
                    java.time.Instant.from(httpDateFormatter.parse(it)).toKotlinInstant()
                }

            val GOOGLE_OFFICIAL_REVOCATION_LIST = "https://android.googleapis.com/attestation/status"
        }
    }


    class FileLoader(
        val path: String,
        override val fallbackRevocationListValiditySeconds: Long,
        private val fallbackToFileSystemInfo: Boolean = true
    ) : CachingLoader() {


        override suspend fun fetch(now: Instant) = withContext(Dispatchers.IO) {
            FileInputStream(path).use { reader ->
                var read = deserialize(json.decodeFromStream<JsonObject>(reader))
                if (fallbackToFileSystemInfo) {
                    if (read.lastModified == null) {
                        val fromFs = java.io.File(path).lastModified()
                        if (fromFs != 0L) read = read.copy(lastModified = Instant.fromEpochMilliseconds(fromFs))
                    }
                    if (read.date == null) {
                        val attrs: BasicFileAttributes =
                            Files.readAttributes(Path.of(path), BasicFileAttributes::class.java)
                        val fromFs = attrs.creationTime().toMillis()
                        if (fromFs != 0L) read = read.copy(date = Instant.fromEpochMilliseconds(fromFs))
                    }
                }

                if (read.expires == null) read =
                    read.copy(expires = now + fallbackRevocationListValiditySeconds.seconds)
                read
            }
        }


        @Serializable
        @SerialName("file")
        data class Configuration(
            val path: String,
            override val fallbackRevocationListValiditySeconds: Long = 0,
            val fallbackToFileSystemInfo: Boolean = true
        ) : Loader.Configuration<FileLoader> {
            override fun createLoader() =
                FileLoader(path, fallbackRevocationListValiditySeconds, fallbackToFileSystemInfo)

        }
    }
}

@OptIn(ExperimentalTime::class)
private object Iso8601YyyMmDdSerializer : KSerializer<Instant> {
    override val descriptor = PrimitiveSerialDescriptor("Iso8601YyyMmDd", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: Instant) {
        encoder.encodeString(value.toString().take(10))
    }

    override fun deserialize(decoder: Decoder): Instant {
        return Instant.parse(decoder.decodeString())
    }

}
