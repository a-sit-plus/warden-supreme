package at.asitplus.attestation.android

import at.asitplus.attestation.DebugStatement
import at.asitplus.attestation.android.AndroidRevocationList.Loader.Configuration
import at.asitplus.attestation.wardenVersion
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import java.security.cert.X509Certificate
import kotlin.time.Instant

internal val jsonDebug by lazy {
    Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = true
        serializersModule = AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e }
        classDiscriminator = "type"
    }
}

private val jsonCompact by lazy {
    Json {
        encodeDefaults = true
        ignoreUnknownKeys = true
        prettyPrint = false
        serializersModule = AndroidRevocationList.loaderRegistry.modules.reduce { acc, e -> acc + e }
        classDiscriminator = "type"
    }
}

@Serializable
data class ConfigWithList(val config: Configuration<*>, val list: AndroidRevocationList)

@Serializable
class AndroidDebugAttestationStatement(
    override val version: String,
    val configuration: AndroidAttestationConfiguration,
    val verificationTime: Instant,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray,
    val attestationStatement: List<@Serializable(with = CertPemSerializer::class) X509Certificate>,
    val revocationLists: List<ConfigWithList>,
) : DebugStatement<Any> {

    init {
        require(version == wardenVersion) { "Version mismatch! This debug statement was created using Warden Supreme $version. The current version is $wardenVersion" }
    }

    fun checkerFromConfig(): Roboto = Roboto(configuration)

    override suspend fun replay() =
        checkerFromConfig().verify(attestationStatement, verificationTime, challenge)

    //todo replayBlocking as extension on interface

    override fun serialize() = jsonDebug.encodeToString(this)

    override fun serializeCompact() =
        MultiBase.encode(MultiBase.Base.BASE64_URL, jsonCompact.encodeToString(this).encodeToByteArray())

    override fun toJsonElement(): JsonObject = jsonDebug.encodeToJsonElement(this).jsonObject

    @Serializable
    enum class Type {
        HARDWARE, SOFTWARE
    }

    //Reader<D, R : DebugStatement<R>>
    companion object : DebugStatement.Reader<Any, AndroidDebugAttestationStatement> {

        suspend operator fun invoke(
            verifier: Roboto,
            configuration: AndroidAttestationConfiguration,
            verificationTime: Instant,
            challenge: ByteArray,
            attestationStatement: List<X509Certificate>
        ) = AndroidDebugAttestationStatement(
            wardenVersion,
            configuration,
            verificationTime,
            challenge,
            attestationStatement,
            verifier.revocationListsFromLastCall()
        )

        override fun deserialize(string: String): AndroidDebugAttestationStatement =
            jsonDebug.decodeFromString<AndroidDebugAttestationStatement>(string)


        override fun deserializeCompact(string: String): AndroidDebugAttestationStatement =
            jsonCompact.decodeFromString(MultiBase.decode(string)!!.decodeToString())

        override fun fromJsonElement(jsonElement: JsonElement): AndroidDebugAttestationStatement =
            jsonDebug.decodeFromJsonElement(jsonElement)
    }
}
