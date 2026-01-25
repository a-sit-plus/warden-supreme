package at.asitplus.attestation.android

import at.asitplus.attestation.DebugStatement
import at.asitplus.attestation.android.AndroidRevocationList.Loader.Configuration
import at.asitplus.attestation.wardenVersion
import at.asitplus.io.MultiBase
import at.asitplus.signum.indispensable.io.ByteArrayBase64UrlSerializer
import com.google.android.attestation.ParsedAttestationRecord
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.*
import kotlinx.serialization.modules.plus
import java.security.cert.X509Certificate
import java.util.*

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
    val kind: Type,
    val configuration: AndroidAttestationConfiguration,
    @Serializable(with = DateTimeSerializer::class) val verificationTime: Date,
    @Serializable(with = ByteArrayBase64UrlSerializer::class) val challenge: ByteArray,
    val attestationStatement: List<@Serializable(with = CertPemSerializer::class) X509Certificate>,
    val revocationLists: List<ConfigWithList>,
) : DebugStatement<ParsedAttestationRecord> {

    init {
        require(version == wardenVersion) { "Version mismatch! This debug statement was created using Warden Supreme $version. The current version is $wardenVersion" }
    }

    fun checkerFromConfig(): Roboto =
        when (kind) {
            Type.HARDWARE -> HardwareAttestationVerifier(configuration)
            Type.SOFTWARE -> SoftwareAttestationVerifier(configuration)
        }

    override suspend fun replay() =
        checkerFromConfig().verifyAttestation(attestationStatement, verificationTime, challenge)

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
    companion object : DebugStatement.Reader<ParsedAttestationRecord, AndroidDebugAttestationStatement> {

        suspend operator fun invoke(
            verifier: Roboto,
            configuration: AndroidAttestationConfiguration,
            verificationTime: Date,
            challenge: ByteArray,
            attestationStatement: List<X509Certificate>
        ) = AndroidDebugAttestationStatement(
            wardenVersion,
            when (verifier) {
                is HardwareAttestationVerifier -> Type.HARDWARE
                is SoftwareAttestationVerifier -> Type.SOFTWARE
                else -> throw IllegalArgumentException("Unknown checker type")
            },
            configuration,
            verificationTime,
            challenge,
            attestationStatement,
            verifier.revocationListFromLastCall()
        )

        override fun deserialize(string: String): AndroidDebugAttestationStatement =
            jsonDebug.decodeFromString<AndroidDebugAttestationStatement>(string)


        override fun deserializeCompact(string: String): AndroidDebugAttestationStatement =
            jsonCompact.decodeFromString(MultiBase.decode(string)!!.decodeToString())

        override fun fromJsonElement(jsonElement: JsonElement): AndroidDebugAttestationStatement =
            jsonDebug.decodeFromJsonElement(jsonElement)
    }
}
